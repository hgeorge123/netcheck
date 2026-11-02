package runner

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// fakeICMP answers each probe from a script keyed by sequence/TTL.
type fakeICMP struct {
	events map[int]ICMPEvent // by seq (ping) or ttl (traceroute)
	probes []int
	closed bool
}

func (f *fakeICMP) Probe(_ context.Context, _ netip.Addr, seq, _ int, _ time.Duration) (ICMPEvent, error) {
	f.probes = append(f.probes, seq)
	if ev, ok := f.events[seq]; ok {
		return ev, nil
	}
	return ICMPEvent{Kind: ICMPTimeout}, nil
}

func (f *fakeICMP) Close() error { f.closed = true; return nil }

func icmpRunner(f *fakeICMP) *Runner {
	return &Runner{Resolver: &fakeResolver{}, Dialer: blockingDialer{}, ICMP: func(bool) (ICMPConn, error) { return f, nil }}
}

func pingCheck(count int) probes.Check {
	return probes.Check{Method: probes.MethodPing, Ping: &probes.PingOptions{Count: count}, TimeoutMS: 30000}
}

func reply(from string, rtt time.Duration) ICMPEvent {
	return ICMPEvent{Kind: ICMPEchoReply, From: netip.MustParseAddr(from), RTT: rtt}
}

func TestPingOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		events   map[int]ICMPEvent
		status   string
		category string
		received int
	}{
		{"all replies", map[int]ICMPEvent{1: reply("10.0.0.9", 2*time.Millisecond), 2: reply("10.0.0.9", 4*time.Millisecond)}, probes.StatusSucceeded, diagnostics.CategoryOK, 2},
		{"partial loss", map[int]ICMPEvent{1: reply("10.0.0.9", time.Millisecond)}, probes.StatusSucceeded, diagnostics.CategoryICMPPartialLoss, 1},
		{"no reply", map[int]ICMPEvent{}, probes.StatusFailed, diagnostics.CategoryICMPNoReply, 0},
		{"unreachable", map[int]ICMPEvent{1: {Kind: ICMPUnreachable, From: netip.MustParseAddr("10.0.0.1"), Code: 13}}, probes.StatusFailed, diagnostics.CategoryICMPUnreachable, 0},
	}
	for _, c := range cases {
		f := &fakeICMP{events: c.events}
		cr := one(t, icmpRunner(f), mkSpec(t, "10.0.0.9", 0, pingCheck(2)))
		if cr.Status != c.status || cr.Category != c.category || cr.Ping == nil || cr.Ping.Received != c.received || cr.Ping.Transmitted != 2 {
			t.Errorf("%s: %+v ping=%+v", c.name, cr, cr.Ping)
		}
		if !f.closed {
			t.Errorf("%s: socket not closed", c.name)
		}
	}
	f := &fakeICMP{events: map[int]ICMPEvent{1: reply("10.0.0.9", 2*time.Millisecond), 2: reply("10.0.0.9", 4*time.Millisecond)}}
	cr := one(t, icmpRunner(f), mkSpec(t, "10.0.0.9", 0, pingCheck(2)))
	if cr.Ping.MinMS != 2 || cr.Ping.MaxMS != 4 || cr.Ping.AvgMS != 3 || cr.Ping.LossPercent != 0 || cr.Equivalent[0] != "ping" {
		t.Errorf("stats = %+v argv=%v", cr.Ping, cr.Equivalent)
	}
}

func TestICMPNotPermittedIsPlatformIssue(t *testing.T) {
	r := &Runner{Resolver: &fakeResolver{}, Dialer: blockingDialer{}, ICMP: func(bool) (ICMPConn, error) { return nil, ErrICMPNotPermitted }}
	cr := one(t, r, mkSpec(t, "10.0.0.9", 0, pingCheck(1)))
	if cr.Category != diagnostics.CategoryICMPNotPermitted || cr.Status != probes.StatusFailed {
		t.Fatalf("result = %+v", cr)
	}
}

func TestICMPRespectsDestinationPolicy(t *testing.T) {
	f := &fakeICMP{}
	cr := one(t, icmpRunner(f), mkSpec(t, "169.254.169.254", 0, probes.Check{Method: probes.MethodTraceroute, Traceroute: &probes.TracerouteOptions{MaxHops: 3}, TimeoutMS: 5000}))
	if cr.Category != diagnostics.CategoryDestinationDenied || len(f.probes) != 0 {
		t.Fatalf("denied destination probed: %+v probes=%v", cr, f.probes)
	}
}

func TestTraceroute(t *testing.T) {
	hop := func(addr string) ICMPEvent {
		return ICMPEvent{Kind: ICMPTTLExceeded, From: netip.MustParseAddr(addr), RTT: time.Millisecond}
	}
	trace := func(maxHops int) probes.Check {
		return probes.Check{Method: probes.MethodTraceroute, Traceroute: &probes.TracerouteOptions{MaxHops: maxHops}, TimeoutMS: 30000}
	}
	// Reached at hop 3; hop 2 silent.
	f := &fakeICMP{events: map[int]ICMPEvent{1: hop("10.0.0.1"), 3: reply("10.0.0.9", 3*time.Millisecond)}}
	cr := one(t, icmpRunner(f), mkSpec(t, "10.0.0.9", 0, trace(10)))
	tr := cr.Traceroute
	if cr.Status != probes.StatusSucceeded || !tr.Reached || len(tr.Hops) != 3 || tr.Hops[1].Address != "" || tr.Hops[2].Address != "10.0.0.9" {
		t.Fatalf("reached: %+v %+v", cr, tr)
	}
	if len(f.probes) != 3 {
		t.Errorf("must stop when the destination answers, probes=%v", f.probes)
	}

	// Never reached: inconclusive, not a hard failure.
	f = &fakeICMP{events: map[int]ICMPEvent{1: hop("10.0.0.1")}}
	cr = one(t, icmpRunner(f), mkSpec(t, "10.0.0.9", 0, trace(4)))
	if cr.Category != diagnostics.CategoryTracerouteIncomplete || cr.Traceroute.Reached || len(cr.Traceroute.Hops) != 4 {
		t.Fatalf("incomplete: %+v %+v", cr, cr.Traceroute)
	}

	// Unreachable stops the trace.
	f = &fakeICMP{events: map[int]ICMPEvent{1: hop("10.0.0.1"), 2: {Kind: ICMPUnreachable, From: netip.MustParseAddr("10.0.0.2"), Code: 13}}}
	cr = one(t, icmpRunner(f), mkSpec(t, "10.0.0.9", 0, trace(10)))
	if len(cr.Traceroute.Hops) != 2 || cr.Traceroute.Hops[1].Note == "" {
		t.Fatalf("unreachable: %+v", cr.Traceroute)
	}
}
