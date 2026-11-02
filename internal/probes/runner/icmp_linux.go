//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// linuxICMP is an unprivileged ICMP "ping socket". The kernel assigns the
// echo identifier and only delivers our own replies; ICMP errors from routers
// (time exceeded, unreachable) arrive on the socket error queue thanks to
// IP_RECVERR / IPV6_RECVERR, which is how traceroute works without NET_RAW.
type linuxICMP struct {
	fd int
	v6 bool
}

func dialICMP(v6 bool) (ICMPConn, error) {
	domain, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if v6 {
		domain, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EPROTONOSUPPORT) {
			return nil, fmt.Errorf("%w: %v", ErrICMPNotPermitted, err)
		}
		return nil, err
	}
	level, opt := unix.IPPROTO_IP, unix.IP_RECVERR
	if v6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
	}
	if err := unix.SetsockoptInt(fd, level, opt, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("enable RECVERR: %w", err)
	}
	return &linuxICMP{fd: fd, v6: v6}, nil
}

func (c *linuxICMP) Close() error { return unix.Close(c.fd) }

func (c *linuxICMP) setTTL(ttl int) error {
	if c.v6 {
		return unix.SetsockoptInt(c.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
	}
	return unix.SetsockoptInt(c.fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
}

func (c *linuxICMP) Probe(ctx context.Context, dst netip.Addr, seq, ttl int, wait time.Duration) (ICMPEvent, error) {
	if err := c.setTTL(ttl); err != nil {
		return ICMPEvent{}, err
	}
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if c.v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{Seq: seq, Data: []byte("netcheck-probe")}}
	b, err := msg.Marshal(nil) // the kernel fills the identifier and the ICMPv6 checksum
	if err != nil {
		return ICMPEvent{}, err
	}
	var sa unix.Sockaddr
	if c.v6 {
		sa = &unix.SockaddrInet6{Addr: dst.As16()}
	} else {
		sa = &unix.SockaddrInet4{Addr: dst.Unmap().As4()}
	}
	start := time.Now()
	if err := unix.Sendto(c.fd, b, 0, sa); err != nil {
		// A local error (e.g. no route) is reported like an unreachable answer.
		if errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENETUNREACH) {
			return ICMPEvent{Kind: ICMPUnreachable, RTT: time.Since(start)}, nil
		}
		return ICMPEvent{}, err
	}
	deadline := start.Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			return ICMPEvent{Kind: ICMPTimeout}, nil
		}
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(fds, int(remaining.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return ICMPEvent{}, err
		}
		if n == 0 {
			return ICMPEvent{Kind: ICMPTimeout}, nil
		}
		if fds[0].Revents&unix.POLLERR != 0 {
			if ev, ok := c.readErrQueue(buf, oob, seq); ok {
				ev.RTT = time.Since(start)
				return ev, nil
			}
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			if ev, ok := c.readReply(buf, seq); ok {
				ev.RTT = time.Since(start)
				return ev, nil
			}
		}
	}
}

func (c *linuxICMP) proto() int {
	if c.v6 {
		return 58
	}
	return 1
}

// readReply reads one datagram and reports whether it is our echo reply.
func (c *linuxICMP) readReply(buf []byte, seq int) (ICMPEvent, bool) {
	n, from, err := unix.Recvfrom(c.fd, buf, unix.MSG_DONTWAIT)
	if err != nil || n == 0 {
		return ICMPEvent{}, false
	}
	m, err := icmp.ParseMessage(c.proto(), buf[:n])
	if err != nil {
		return ICMPEvent{}, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || echo.Seq != seq || (m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply) {
		return ICMPEvent{}, false
	}
	return ICMPEvent{Kind: ICMPEchoReply, From: sockaddrAddr(from)}, true
}

// readErrQueue reads one ICMP error about our request from the error queue.
func (c *linuxICMP) readErrQueue(buf, oob []byte, seq int) (ICMPEvent, bool) {
	n, oobn, _, _, err := unix.Recvmsg(c.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return ICMPEvent{}, false
	}
	// The payload is the original echo request: match its sequence number.
	if m, err := icmp.ParseMessage(c.proto(), buf[:n]); err == nil {
		if echo, ok := m.Body.(*icmp.Echo); ok && echo.Seq != seq {
			return ICMPEvent{}, false
		}
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return ICMPEvent{}, false
	}
	for _, cm := range cmsgs {
		ipErr := cm.Header.Level == unix.IPPROTO_IP && cm.Header.Type == unix.IP_RECVERR
		ip6Err := cm.Header.Level == unix.IPPROTO_IPV6 && cm.Header.Type == unix.IPV6_RECVERR
		if !ipErr && !ip6Err {
			continue
		}
		if ev, ok := parseExtendedErr(cm.Data); ok {
			return ev, true
		}
	}
	return ICMPEvent{}, false
}

// parseExtendedErr decodes a sock_extended_err followed by the offender
// sockaddr (the router or host that sent the ICMP error).
func parseExtendedErr(data []byte) (ICMPEvent, bool) {
	const eeSize = int(unsafe.Sizeof(unix.SockExtendedErr{}))
	if len(data) < eeSize {
		return ICMPEvent{}, false
	}
	ee := (*unix.SockExtendedErr)(unsafe.Pointer(&data[0]))
	ev := ICMPEvent{Code: int(ee.Code), From: offender(data[eeSize:])}
	switch {
	case ee.Origin == unix.SO_EE_ORIGIN_ICMP && ee.Type == 11, ee.Origin == unix.SO_EE_ORIGIN_ICMP6 && ee.Type == 3:
		ev.Kind = ICMPTTLExceeded
	case ee.Origin == unix.SO_EE_ORIGIN_ICMP && ee.Type == 3, ee.Origin == unix.SO_EE_ORIGIN_ICMP6 && ee.Type == 1:
		ev.Kind = ICMPUnreachable
	default:
		return ICMPEvent{}, false
	}
	return ev, true
}

// offender parses a raw sockaddr_in / sockaddr_in6 (host byte order family).
func offender(b []byte) netip.Addr {
	if len(b) < 2 {
		return netip.Addr{}
	}
	family := *(*uint16)(unsafe.Pointer(&b[0]))
	switch {
	case family == unix.AF_INET && len(b) >= 8:
		return netip.AddrFrom4([4]byte(b[4:8]))
	case family == unix.AF_INET6 && len(b) >= 24:
		return netip.AddrFrom16([16]byte(b[8:24]))
	}
	return netip.Addr{}
}

func sockaddrAddr(sa unix.Sockaddr) netip.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(a.Addr)
	}
	return netip.Addr{}
}
