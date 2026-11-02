package probes

import (
	"errors"
	"net/netip"
	"testing"
)

func labPolicy() *CompiledPolicy {
	p := DestinationPolicy{
		AllowCIDRs:            []string{"10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0"},
		AllowHostnameSuffixes: []string{".svc.cluster.local", "corp.example.com"},
		AllowPorts:            []PortRange{{From: 80, To: 80}, {From: 443, To: 443}, {From: 8000, To: 8999}},
	}.WithBuiltinDenies("10.96.0.1/32")
	c, err := p.Compile()
	if err != nil {
		panic(err)
	}
	return c
}

func TestCheckIPDenyWinsOverAllow(t *testing.T) {
	c := labPolicy()
	denied := []string{
		"169.254.169.254",        // cloud metadata
		"::ffff:169.254.169.254", // IPv4-mapped bypass attempt
		"127.0.0.1",
		"::1",
		"fe80::1",
		"fd00:ec2::254", // AWS IMDS IPv6
		"10.96.0.1",     // kubernetes service IP (extra deny)
		"224.0.0.1",
		"0.0.0.0",
	}
	for _, s := range denied {
		err := c.CheckIP(netip.MustParseAddr(s))
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Errorf("CheckIP(%s) = %v, want DeniedError", s, err)
		}
	}
	for _, s := range []string{"10.20.30.40", "2001:db8::10", "8.8.8.8", "::ffff:10.1.1.1"} {
		if err := c.CheckIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("CheckIP(%s) = %v, want allowed", s, err)
		}
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	c, err := DestinationPolicy{}.WithBuiltinDenies().Compile()
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckIP(netip.MustParseAddr("10.0.0.1")) == nil {
		t.Error("empty allowlist must deny IPs")
	}
	if c.CheckHostname("example.com") == nil {
		t.Error("empty allowlist must deny hostnames")
	}
	if c.CheckPort(443) == nil {
		t.Error("empty allowlist must deny ports")
	}
}

func TestCheckHostnameSuffixBoundaries(t *testing.T) {
	c := labPolicy()
	allowed := []string{"api.payments.svc.cluster.local", "corp.example.com", "a.corp.example.com"}
	for _, h := range allowed {
		if err := c.CheckHostname(h); err != nil {
			t.Errorf("CheckHostname(%s) = %v", h, err)
		}
	}
	for _, h := range []string{"evilcorp.example.com", "svc.cluster.local", "corp.example.com.evil.io", "example.com"} {
		if c.CheckHostname(h) == nil {
			t.Errorf("CheckHostname(%s) should be denied", h)
		}
	}
}

func TestCheckPortRanges(t *testing.T) {
	c := labPolicy()
	for _, p := range []int{80, 443, 8000, 8500, 8999} {
		if c.CheckPort(p) != nil {
			t.Errorf("port %d should be allowed", p)
		}
	}
	for _, p := range []int{22, 79, 9000, 6443} {
		if c.CheckPort(p) == nil {
			t.Errorf("port %d should be denied", p)
		}
	}
}

func TestCompileRejectsInvalid(t *testing.T) {
	bad := []DestinationPolicy{
		{AllowCIDRs: []string{"10.0.0.0/33"}},
		{DenyCIDRs: []string{"not-a-cidr"}},
		{AllowCIDRs: []string{"::ffff:10.0.0.0/104"}},
		{AllowHostnameSuffixes: []string{"bad_suffix"}},
		{AllowPorts: []PortRange{{From: 0, To: 10}}},
		{AllowPorts: []PortRange{{From: 100, To: 10}}},
	}
	for i, p := range bad {
		if _, err := p.Compile(); err == nil {
			t.Errorf("policy %d should fail to compile", i)
		}
	}
}

func TestWithBuiltinDeniesCannotBeRemoved(t *testing.T) {
	p := DestinationPolicy{DenyCIDRs: []string{"192.0.2.0/24"}}.WithBuiltinDenies()
	found := map[string]bool{}
	for _, d := range p.DenyCIDRs {
		found[d] = true
	}
	for _, b := range BuiltinDenyCIDRs {
		if !found[b] {
			t.Errorf("builtin deny %s missing", b)
		}
	}
	if !found["192.0.2.0/24"] {
		t.Error("configured deny lost")
	}
}
