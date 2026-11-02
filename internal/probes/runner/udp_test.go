package runner

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// udpServer answers every datagram with reply(request); a nil reply keeps
// the server silent.
func udpServer(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := reply(append([]byte(nil), buf[:n]...)); out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return portOf(t, pc.LocalAddr().String())
}

func udpCheck(protocol string, timeoutMS int) probes.Check {
	return probes.Check{Method: probes.MethodUDP, UDP: &probes.UDPOptions{Protocol: protocol}, TimeoutMS: timeoutMS}
}

func TestUDPGenericReply(t *testing.T) {
	port := udpServer(t, func([]byte) []byte { return []byte("pong") })
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPGeneric, 3000)))
	if cr.Status != probes.StatusSucceeded || cr.Category != diagnostics.CategoryOK || cr.UDP == nil || cr.UDP.ReplyBytes != 4 {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
	if cr.Equivalent[0] != "nc" || cr.Equivalent[1] != "-u" {
		t.Errorf("equivalent argv = %v", cr.Equivalent)
	}
}

func TestUDPGenericSilenceIsInconclusive(t *testing.T) {
	port := udpServer(t, func([]byte) []byte { return nil })
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPGeneric, 600)))
	if cr.Status != probes.StatusTimedOut || cr.Category != diagnostics.CategoryUDPNoReply || cr.UDP.Attempts != udpAttempts {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
}

func TestUDPDNS(t *testing.T) {
	port := udpServer(t, func(req []byte) []byte {
		var m dnsmessage.Message
		if err := m.Unpack(req); err != nil || len(m.Questions) != 1 || m.Questions[0].Type != dnsmessage.TypeNS {
			return nil
		}
		m.Response = true
		m.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.root-servers.net.")},
		}}
		out, _ := m.Pack()
		return out
	})
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPDNS, 3000)))
	if cr.Status != probes.StatusSucceeded || cr.UDP.DNSRcode != "NOERROR" || cr.UDP.DNSAnswers != 1 {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
	if cr.Equivalent[0] != "dig" {
		t.Errorf("equivalent argv = %v", cr.Equivalent)
	}
}

func TestUDPDNSRefusedStillProvesTheService(t *testing.T) {
	port := udpServer(t, func(req []byte) []byte {
		var m dnsmessage.Message
		if err := m.Unpack(req); err != nil {
			return nil
		}
		m.Response, m.RCode, m.Answers = true, dnsmessage.RCodeRefused, nil
		out, _ := m.Pack()
		return out
	})
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPDNS, 3000)))
	if cr.Status != probes.StatusSucceeded || cr.UDP.DNSRcode != "REFUSED" {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
}

// A DNS server that answers the first query only after the second one was
// sent (a resolver waiting for its upstream) must still count as a reply.
func TestUDPLateReplyToAnEarlierDatagram(t *testing.T) {
	var first []byte
	port := udpServer(t, func(req []byte) []byte {
		if first == nil {
			first = req
			return nil
		}
		var m dnsmessage.Message
		if err := m.Unpack(first); err != nil {
			return nil
		}
		m.Response, m.RCode = true, dnsmessage.RCodeServerFailure
		out, _ := m.Pack()
		return out // the answer to the first query, sent when the second arrives
	})
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPDNS, 1500)))
	if cr.Status != probes.StatusSucceeded || cr.UDP.DNSRcode != "SERVFAIL" || cr.UDP.Attempts != 2 {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
}

func TestUDPWrongProtocolIsUnexpected(t *testing.T) {
	port := udpServer(t, func([]byte) []byte { return []byte("not dns") })
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPDNS, 600)))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryUDPUnexpected {
		t.Fatalf("result = %+v", cr)
	}
}

func TestUDPNTP(t *testing.T) {
	port := udpServer(t, func(req []byte) []byte {
		if len(req) != 48 || req[0]&0x7 != 3 {
			return nil
		}
		now := toNTP(time.Now())
		out := make([]byte, 48)
		out[0] = 0<<6 | 4<<3 | 4 // server
		out[1] = 2               // stratum
		copy(out[12:16], []byte{10, 0, 0, 1})
		copy(out[24:32], req[40:48]) // origin = client transmit
		binary.BigEndian.PutUint64(out[32:], now)
		binary.BigEndian.PutUint64(out[40:], now)
		return out
	})
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, udpCheck(probes.UDPNTP, 3000)))
	if cr.Status != probes.StatusSucceeded || cr.UDP.NTPStratum != 2 || cr.UDP.NTPReference != "10.0.0.1" {
		t.Fatalf("result = %+v udp=%+v", cr, cr.UDP)
	}
	if cr.UDP.NTPOffsetMS > 1000 || cr.UDP.NTPOffsetMS < -1000 {
		t.Errorf("offset = %v ms", cr.UDP.NTPOffsetMS)
	}
}

func TestUDPPolicyDeniedNeverSends(t *testing.T) {
	r, d := newRunner(nil)
	cr := one(t, r, mkSpec(t, "169.254.169.254", 53, udpCheck(probes.UDPDNS, 1000)))
	if cr.Category != diagnostics.CategoryDestinationDenied || d.calls.Load() != 0 {
		t.Fatalf("result = %+v, dials = %d", cr, d.calls.Load())
	}
}

func TestNTPTimestampRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)
	if got := fromNTP(toNTP(now)); got.Sub(now).Abs() > time.Microsecond {
		t.Fatalf("round trip %v -> %v", now, got)
	}
}
