package runner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// udpAttempts datagrams are sent per check, spread over its timeout, because
// UDP gives no delivery guarantee.
const udpAttempts = 3

// errNoUDPReply marks a UDP check that got no answer at all.
var errNoUDPReply = errors.New("no UDP reply")

// udpExchange is one protocol: the datagram to send and how to recognise and
// read the matching answer. accept returns false for unrelated datagrams.
type udpExchange struct {
	payload []byte
	accept  func(reply []byte, sent, received time.Time, u *probes.UDPResult) bool
}

func (r *Runner) runUDP(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	if err := policy.CheckPort(c.Port); err != nil {
		return err
	}
	allowed, err := r.resolve(ctx, spec.Target, "ip", policy, cr, st)
	if err != nil {
		return err
	}
	ip := allowed[0]
	cr.UsedIP = ip.String()
	u := &probes.UDPResult{Protocol: c.UDP.Protocol}
	cr.UDP = u
	cr.Equivalent = udpEquivalent(c, ip)

	addr := net.JoinHostPort(ip.String(), strconv.Itoa(c.Port))
	// A connected socket only receives datagrams from the destination and
	// reports its ICMP port unreachable as ECONNREFUSED, without privileges.
	conn, err := r.Dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	st.printf("udp %s -> %s (%s)", conn.LocalAddr(), addr, u.Protocol)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	perAttempt := time.Until(deadline) / udpAttempts
	buf := make([]byte, 2048)
	unexpected := false
	// A slow server (e.g. a DNS resolver waiting for its upstream) may answer
	// an earlier datagram after the next one was sent: every datagram sent so
	// far stays valid until the deadline.
	type pending struct {
		x    udpExchange
		sent time.Time
	}
	var sent []pending
	for attempt := 1; attempt <= udpAttempts && ctx.Err() == nil; attempt++ {
		x, err := newUDPExchange(u.Protocol)
		if err != nil {
			return err
		}
		u.Attempts = attempt
		now := time.Now()
		if _, err := conn.Write(x.payload); err != nil {
			return udpError(err, cr)
		}
		sent = append(sent, pending{x, now})
		_ = conn.SetReadDeadline(minTime(deadline, now.Add(perAttempt)))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					st.printf("attempt %d: no reply", attempt)
					break
				}
				return udpError(err, cr)
			}
			received := time.Now()
			match := -1
			for i := len(sent) - 1; i >= 0 && match < 0; i-- {
				if sent[i].x.accept(buf[:n], sent[i].sent, received, u) {
					match = i
				}
			}
			if match < 0 {
				unexpected = true
				st.printf("attempt %d: %d bytes that are not a %s reply", attempt, n, u.Protocol)
				continue
			}
			u.ReplyBytes = n
			u.RTTMS = float64(received.Sub(sent[match].sent).Microseconds()) / 1000
			st.printf("reply to datagram %d: %d bytes in %.1f ms%s", match+1, n, u.RTTMS, udpReplySummary(u))
			return nil
		}
	}
	if unexpected {
		cr.Category = diagnostics.CategoryUDPUnexpected
		return fmt.Errorf("the destination answered, but not with a %s reply", u.Protocol)
	}
	cr.Category = diagnostics.CategoryUDPNoReply
	return fmt.Errorf("%w after %d datagrams: the port may be open or filtered", errNoUDPReply, u.Attempts)
}

// udpError maps a socket error: ECONNREFUSED on UDP means an ICMP port
// unreachable came back, i.e. the host was reached and the port is closed.
func udpError(err error, cr *probes.CheckResult) error {
	cat := diagnostics.Classify(err, isDenied)
	if cat == diagnostics.CategoryTCPRefused {
		cat = diagnostics.CategoryUDPPortClosed
	}
	cr.Category = cat
	return err
}

func newUDPExchange(protocol string) (udpExchange, error) {
	switch protocol {
	case probes.UDPGeneric:
		// Empty datagram: any answer from the destination counts.
		return udpExchange{accept: func([]byte, time.Time, time.Time, *probes.UDPResult) bool { return true }}, nil
	case probes.UDPDNS:
		return dnsExchange()
	case probes.UDPNTP:
		return ntpExchange(), nil
	}
	return udpExchange{}, fmt.Errorf("udp protocol %q not supported", protocol)
}

// dnsExchange asks for the root NS records, which any DNS server answers
// (with data, a referral or an error code): every answer proves the service.
func dnsExchange() (udpExchange, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return udpExchange{}, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}},
	}
	payload, err := msg.Pack()
	if err != nil {
		return udpExchange{}, err
	}
	return udpExchange{payload: payload, accept: func(reply []byte, _, _ time.Time, u *probes.UDPResult) bool {
		var p dnsmessage.Parser
		h, err := p.Start(reply)
		if err != nil || h.ID != id || !h.Response {
			return false
		}
		u.DNSRcode = dnsRcodeName(h.RCode)
		if err := p.SkipAllQuestions(); err == nil {
			if answers, err := p.AllAnswers(); err == nil {
				u.DNSAnswers = len(answers)
			}
		}
		return true
	}}, nil
}

func dnsRcodeName(rc dnsmessage.RCode) string {
	names := map[dnsmessage.RCode]string{
		dnsmessage.RCodeSuccess: "NOERROR", dnsmessage.RCodeFormatError: "FORMERR", dnsmessage.RCodeServerFailure: "SERVFAIL",
		dnsmessage.RCodeNameError: "NXDOMAIN", dnsmessage.RCodeNotImplemented: "NOTIMP", dnsmessage.RCodeRefused: "REFUSED",
	}
	if n, ok := names[rc]; ok {
		return n
	}
	return "RCODE" + strconv.Itoa(int(rc))
}

// NTP timestamps count seconds since 1900; Unix time starts 70 years later.
const ntpEpochOffset = 2208988800

func toNTP(t time.Time) uint64 {
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return secs<<32 | frac
}

func fromNTP(v uint64) time.Time {
	secs := int64(v>>32) - ntpEpochOffset
	nanos := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(secs, nanos)
}

// ntpExchange sends an NTPv4 client request (mode 3). The server echoes our
// transmit timestamp as its origin timestamp, which identifies the answer.
func ntpExchange() udpExchange {
	payload := make([]byte, 48)
	payload[0] = 0<<6 | 4<<3 | 3 // LI 0, version 4, mode 3 (client)
	sentStamp := toNTP(time.Now())
	binary.BigEndian.PutUint64(payload[40:], sentStamp)
	return udpExchange{payload: payload, accept: func(reply []byte, sent, received time.Time, u *probes.UDPResult) bool {
		if len(reply) < 48 || reply[0]&0x7 != 4 || binary.BigEndian.Uint64(reply[24:]) != sentStamp {
			return false
		}
		u.NTPStratum = int(reply[1])
		ref := reply[12:16]
		if u.NTPStratum <= 1 {
			u.NTPReference = string(trimZeros(ref)) // kiss code or reference clock id
		} else {
			u.NTPReference = netip.AddrFrom4([4]byte(ref)).String()
		}
		// Clock offset of the probe: ((T2 - T1) + (T3 - T4)) / 2.
		t2 := fromNTP(binary.BigEndian.Uint64(reply[32:]))
		t3 := fromNTP(binary.BigEndian.Uint64(reply[40:]))
		offset := (t2.Sub(sent) + t3.Sub(received)) / 2
		u.NTPOffsetMS = math.Round(float64(offset.Microseconds())/10) / 100
		return true
	}}
}

func trimZeros(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func udpReplySummary(u *probes.UDPResult) string {
	switch u.Protocol {
	case probes.UDPDNS:
		return fmt.Sprintf(", DNS %s with %d answers", u.DNSRcode, u.DNSAnswers)
	case probes.UDPNTP:
		return fmt.Sprintf(", NTP stratum %d (%s), offset %.2f ms", u.NTPStratum, u.NTPReference, u.NTPOffsetMS)
	}
	return ""
}

// udpEquivalent is an approximate shell command for the same check.
func udpEquivalent(c probes.Check, ip netip.Addr) []string {
	secs := strconv.Itoa(max(1, c.TimeoutMS/1000))
	port := strconv.Itoa(c.Port)
	switch c.UDP.Protocol {
	case probes.UDPDNS:
		return []string{"dig", "@" + ip.String(), "-p", port, ".", "NS", "+tries=" + strconv.Itoa(udpAttempts), "+time=" + secs}
	case probes.UDPNTP:
		if c.Port == 123 {
			return []string{"ntpdate", "-q", ip.String()}
		}
	}
	return []string{"nc", "-u", "-z", "-v", "-w", secs, ip.String(), port}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
