package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// ICMP probes use unprivileged "ping sockets" (SOCK_DGRAM + IPPROTO_ICMP),
// enabled for the probe group by the safe sysctl net.ipv4.ping_group_range
// in the Pod spec. No NET_RAW capability is needed, so the probe keeps the
// Pod Security "restricted" profile.

// ICMPEventKind is what came back for one probe.
type ICMPEventKind int

const (
	ICMPTimeout     ICMPEventKind = iota // nothing answered in time
	ICMPEchoReply                        // the destination answered
	ICMPTTLExceeded                      // a router on the path answered (time exceeded)
	ICMPUnreachable                      // a router or the destination answered "unreachable"
)

// ICMPEvent is the outcome of one echo request.
type ICMPEvent struct {
	Kind ICMPEventKind
	From netip.Addr
	RTT  time.Duration
	Code int
}

// ICMPConn sends one echo request with a TTL and waits for its outcome.
type ICMPConn interface {
	Probe(ctx context.Context, dst netip.Addr, seq, ttl int, wait time.Duration) (ICMPEvent, error)
	Close() error
}

// ICMPDialer opens an ICMP connection for IPv4 (v6=false) or IPv6.
type ICMPDialer func(v6 bool) (ICMPConn, error)

// ErrICMPNotPermitted means the node refused unprivileged ICMP sockets.
var ErrICMPNotPermitted = errors.New("unprivileged ICMP sockets are not permitted (net.ipv4.ping_group_range)")

const (
	probeInterval = time.Second
	probeWait     = time.Second
	defaultTTL    = 64
)

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (r *Runner) icmpTarget(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, cr *probes.CheckResult, st *checkState) (netip.Addr, ICMPConn, error) {
	allowed, err := r.resolve(ctx, spec.Target, "ip", policy, cr, st)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	ip := allowed[0]
	cr.UsedIP = ip.String()
	if r.ICMP == nil {
		cr.Category = diagnostics.CategoryICMPNotPermitted
		return ip, nil, ErrICMPNotPermitted
	}
	conn, err := r.ICMP(ip.Is6())
	if err != nil {
		if errors.Is(err, ErrICMPNotPermitted) {
			cr.Category = diagnostics.CategoryICMPNotPermitted
		}
		return ip, nil, err
	}
	return ip, conn, nil
}

func (r *Runner) runPing(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	count := c.Ping.Count
	ip, conn, err := r.icmpTarget(ctx, spec, policy, cr, st)
	if ip.IsValid() {
		cr.Equivalent = []string{"ping", "-n", "-c", strconv.Itoa(count), "-W", "1", ip.String()}
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	res := &probes.PingResult{Replies: []probes.PingReply{}}
	cr.Ping = res
	unreachable := 0
	st.printf("PING %s: %d echo requests", ip, count)
	for seq := 1; seq <= count; seq++ {
		start := time.Now()
		ev, err := conn.Probe(ctx, ip, seq, defaultTTL, probeWait)
		if err != nil {
			return err
		}
		res.Transmitted++
		reply := probes.PingReply{Seq: seq}
		switch ev.Kind {
		case ICMPEchoReply:
			res.Received++
			reply.RTTMS = ms(ev.RTT)
			if res.MinMS == 0 || reply.RTTMS < res.MinMS {
				res.MinMS = reply.RTTMS
			}
			res.MaxMS = max(res.MaxMS, reply.RTTMS)
			res.AvgMS += reply.RTTMS
			st.printf("reply from %s: seq=%d time=%.2f ms", ev.From, seq, reply.RTTMS)
		case ICMPUnreachable, ICMPTTLExceeded:
			unreachable++
			reply.Lost, reply.ErrFrom = true, ev.From.String()
			reply.ErrText = icmpErrText(ev)
			st.printf("seq=%d: %s from %s", seq, reply.ErrText, ev.From)
		default:
			reply.Lost = true
			st.printf("seq=%d: no reply", seq)
		}
		res.Replies = append(res.Replies, reply)
		if seq < count {
			// One request per second, like ping(8).
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(probeInterval - time.Since(start)):
			}
		}
	}
	if res.Received > 0 {
		res.AvgMS /= float64(res.Received)
	}
	res.LossPercent = 100 * float64(res.Transmitted-res.Received) / float64(max(res.Transmitted, 1))
	st.printf("%d transmitted, %d received, %.0f%% loss", res.Transmitted, res.Received, res.LossPercent)
	switch {
	case res.Received == res.Transmitted:
		return nil
	case res.Received > 0:
		cr.Category = diagnostics.CategoryICMPPartialLoss
		return nil
	case unreachable > 0:
		cr.Category = diagnostics.CategoryICMPUnreachable
		return errors.New("destination unreachable")
	default:
		cr.Category = diagnostics.CategoryICMPNoReply
		return errors.New("no ICMP echo replies")
	}
}

func (r *Runner) runTraceroute(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	maxHops := c.Traceroute.MaxHops
	ip, conn, err := r.icmpTarget(ctx, spec, policy, cr, st)
	if ip.IsValid() {
		cr.Equivalent = []string{"traceroute", "-I", "-n", "-q", "1", "-w", "1", "-m", strconv.Itoa(maxHops), ip.String()}
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	res := &probes.TracerouteResult{Protocol: "icmp", MaxHops: maxHops, Hops: []probes.TracerouteHop{}}
	cr.Traceroute = res
	st.printf("traceroute to %s, %d hops max (ICMP)", ip, maxHops)
	for ttl := 1; ttl <= maxHops; ttl++ {
		ev, err := conn.Probe(ctx, ip, ttl, ttl, probeWait)
		if err != nil {
			return err
		}
		hop := probes.TracerouteHop{TTL: ttl}
		if ev.Kind != ICMPTimeout {
			hop.Address, hop.RTTMS = ev.From.String(), ms(ev.RTT)
		}
		if ev.Kind == ICMPUnreachable {
			hop.Note = icmpErrText(ev)
		}
		res.Hops = append(res.Hops, hop)
		if hop.Address == "" {
			st.printf("%2d  *", ttl)
		} else {
			st.printf("%2d  %s  %.2f ms %s", ttl, hop.Address, hop.RTTMS, hop.Note)
		}
		if ev.Kind == ICMPEchoReply {
			res.Reached = true
			return nil
		}
		if ev.Kind == ICMPUnreachable {
			break
		}
	}
	cr.Category = diagnostics.CategoryTracerouteIncomplete
	return errors.New("destination not reached")
}

func icmpErrText(ev ICMPEvent) string {
	switch ev.Kind {
	case ICMPTTLExceeded:
		return "time exceeded"
	case ICMPUnreachable:
		return fmt.Sprintf("destination unreachable (code %d)", ev.Code)
	}
	return ""
}
