package runner

import (
	"net"
	"testing"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// Linux reports the ICMP port unreachable of a closed UDP port to a connected
// socket as ECONNREFUSED; Go disables that report on Windows sockets.
func TestUDPClosedPort(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, pc.LocalAddr().String())
	pc.Close()
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPGeneric, 3000)))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryUDPPortClosed {
		t.Fatalf("result = %+v", cr)
	}
}
