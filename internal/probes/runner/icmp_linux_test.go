//go:build linux

package runner

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Real unprivileged ICMP against loopback. Requires ping_group_range to
// include the test's GID (Docker and Kubernetes probe Pods set it).
func TestLinuxPingSocketLoopback(t *testing.T) {
	conn, err := dialICMP(false)
	if errors.Is(err, ErrICMPNotPermitted) {
		t.Skipf("ping sockets not permitted here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ev, err := conn.Probe(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, 64, time.Second)
	if err != nil || ev.Kind != ICMPEchoReply || ev.From.String() != "127.0.0.1" {
		t.Fatalf("echo = %+v err = %v", ev, err)
	}
	// TTL 1 to loopback is still delivered locally (no router decrements it).
	ev, err = conn.Probe(context.Background(), netip.MustParseAddr("127.0.0.1"), 2, 1, time.Second)
	if err != nil || ev.Kind != ICMPEchoReply {
		t.Fatalf("ttl=1 echo = %+v err = %v", ev, err)
	}
}

func TestLinuxPingSocketTimeout(t *testing.T) {
	conn, err := dialICMP(false)
	if errors.Is(err, ErrICMPNotPermitted) {
		t.Skip("ping sockets not permitted here")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// TEST-NET-1 is never routed: either no answer or a local unreachable.
	ev, err := conn.Probe(context.Background(), netip.MustParseAddr("192.0.2.1"), 1, 64, 300*time.Millisecond)
	if err != nil || (ev.Kind != ICMPTimeout && ev.Kind != ICMPUnreachable) {
		t.Fatalf("unroutable = %+v err = %v", ev, err)
	}
}

func TestParseExtendedErrRejectsGarbage(t *testing.T) {
	if _, ok := parseExtendedErr([]byte{1, 2, 3}); ok {
		t.Error("short buffer accepted")
	}
}
