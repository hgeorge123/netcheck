package probes

import (
	"errors"
	"testing"
)

func TestNormalizeProxies(t *testing.T) {
	got, err := NormalizeProxies([]Proxy{{Name: "corp", Host: "Proxy.Corp.Example", Port: 3128}, {Name: "dmz-2", Host: "10.0.0.9", Port: 8080}})
	if err != nil || got[0].Host != "proxy.corp.example" || got[1].Address() != "10.0.0.9:8080" {
		t.Fatalf("normalize = %+v %v", got, err)
	}
	if empty, err := NormalizeProxies(nil); err != nil || empty == nil {
		t.Errorf("no proxies = %v %v", empty, err)
	}
	many := make([]Proxy, MaxProxies+1)
	for name, tc := range map[string]struct {
		in    []Proxy
		field string
		code  string
	}{
		"bad name":  {[]Proxy{{Name: "Corp Proxy", Host: "p", Port: 1}}, "proxies[0].name", "invalid_proxy_name"},
		"duplicate": {[]Proxy{{Name: "a", Host: "p", Port: 1}, {Name: "a", Host: "q", Port: 2}}, "proxies[1].name", "duplicate_proxy_name"},
		"bad host":  {[]Proxy{{Name: "a", Host: "http://p:3128", Port: 1}}, "proxies[0].host", "invalid_proxy_host"},
		"bad port":  {[]Proxy{{Name: "a", Host: "p", Port: 0}}, "proxies[0].port", "invalid_port"},
		"too many":  {many, "proxies", "too_many_proxies"},
	} {
		_, err := NormalizeProxies(tc.in)
		var fe FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field || fe.Code != tc.code {
			t.Errorf("%s: %+v", name, err)
		}
	}
}

func TestBuildSpecWithProxy(t *testing.T) {
	proxies := []Proxy{{Name: "corp", Host: "10.0.0.9", Port: 8080}, {Name: "outside", Host: "192.0.2.10", Port: 3128}}
	req := RunRequest{Target: "api.payments.svc.cluster.local", Checks: []CheckRequest{
		{Method: MethodHTTPS, Proxy: "corp"}, {Method: MethodTCP, Port: 443, Proxy: "corp"}, {Method: MethodDNS}}}
	spec, err := BuildSpec("abcdef0123456789", req, testPolicy(), testLimits, proxies...)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Checks[0].Proxy == nil || !spec.Checks[0].Proxy.equal(proxies[0]) || spec.Checks[1].Proxy == nil || spec.Checks[2].Proxy != nil {
		t.Fatalf("checks = %+v", spec.Checks)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// HTTP may go through a proxy too; stored proxies are named by ID, and
	// carry their own authorities and the personal mark into the spec.
	stored := Proxy{ID: "p1", Name: "mine", Host: "10.0.0.7", Port: 8080, Personal: true, TrustedCAs: []string{testCert(t, "Proxy CA", true)}}
	httpSpec, err := BuildSpec("abcdef0123456789", RunRequest{Target: "api.payments.svc.cluster.local",
		Checks: []CheckRequest{{Method: MethodHTTP, Proxy: "p1"}}}, testPolicy(), testLimits, stored)
	if err != nil || httpSpec.Checks[0].Proxy == nil || !httpSpec.Checks[0].Proxy.Personal || len(httpSpec.Checks[0].Proxy.TrustedCAs) != 1 {
		t.Fatalf("stored proxy: %+v %v", httpSpec.Checks, err)
	}
	if err := httpSpec.Validate(); err != nil {
		t.Fatalf("validate with proxy authorities: %v", err)
	}
	if _, err := BuildSpec("abcdef0123456789", RunRequest{Target: "api.payments.svc.cluster.local",
		Checks: []CheckRequest{{Method: MethodHTTP, Proxy: "mine"}}}, testPolicy(), testLimits, stored); !codes(err)["proxy_unknown"] {
		t.Errorf("a stored proxy is named by ID, not by name: %v", err)
	}

	for name, tc := range map[string]struct {
		check CheckRequest
		code  string
	}{
		"DNS":       {CheckRequest{Method: MethodDNS, Proxy: "corp"}, "proxy_not_applicable"},
		"UDP":       {CheckRequest{Method: MethodUDP, Port: 53, Proxy: "corp"}, "proxy_not_applicable"},
		"not found": {CheckRequest{Method: MethodTCP, Port: 443, Proxy: "nope"}, "proxy_unknown"},
	} {
		_, err := BuildSpec("abcdef0123456789", RunRequest{Target: "api.payments.svc.cluster.local", Checks: []CheckRequest{tc.check}}, testPolicy(), testLimits, proxies...)
		if !codes(err)[tc.code] {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The proxy must be a destination the policy allows (10.0.0.0/8 here).
	_, err = BuildSpec("abcdef0123456789", RunRequest{Target: "api.payments.svc.cluster.local", Checks: []CheckRequest{{Method: MethodHTTPS, Proxy: "outside"}}},
		testPolicy(), testLimits, proxies...)
	var de *DeniedError
	if !errors.As(err, &de) || de.Reason == "" || de.Reason[:14] != "proxy outside " {
		t.Errorf("proxy outside the policy: %v", err)
	}

	// A tampered spec (proxy on a DNS check, or not normalized) is refused.
	bad := spec
	bad.Checks = append([]Check(nil), spec.Checks...)
	bad.Checks[2].Proxy = &proxies[0]
	if bad.Validate() == nil {
		t.Error("proxy on a DNS check must be refused")
	}
	bad.Checks[2].Proxy = nil
	bad.Checks[0].Proxy = &Proxy{Name: "corp", Host: "UPPER.example", Port: 8080}
	if bad.Validate() == nil {
		t.Error("a proxy that is not normalized must be refused")
	}
	bad.Checks[0].Proxy = &Proxy{Name: "corp", Host: "10.0.0.9", Port: 8080, TrustedCAs: []string{testCert(t, "api.example.com", false)}}
	if bad.Validate() == nil {
		t.Error("a proxy with a server certificate as authority must be refused")
	}
}

func TestNormalizeProxyAuthorities(t *testing.T) {
	ca := testCert(t, "Proxy CA", true)
	p, err := NormalizeProxy(Proxy{Name: "corp", Host: "10.0.0.9", Port: 3128, TrustedCAs: []string{ca + ca, ""}})
	if err != nil || len(p.TrustedCAs) != 1 {
		t.Fatalf("bundle with a duplicate = %+v %v", p, err)
	}
	if p, err := NormalizeProxy(Proxy{Name: "corp", Host: "10.0.0.9", Port: 3128, TrustedCAs: []string{}}); err != nil || p.TrustedCAs != nil {
		t.Errorf("no authorities = %+v %v", p, err)
	}
	for name, tc := range map[string]struct {
		cas  []string
		code string
	}{
		"private key": {[]string{"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}, "not_a_certificate"},
		"too many":    {manyCAs(t, MaxProxyCAs+1), "too_many_certificates"},
	} {
		_, err := NormalizeProxy(Proxy{Name: "corp", Host: "10.0.0.9", Port: 3128, TrustedCAs: tc.cas})
		var fe FieldError
		if !errors.As(err, &fe) || fe.Field != "certificates" || fe.Code != tc.code {
			t.Errorf("%s: %+v", name, err)
		}
	}
}
