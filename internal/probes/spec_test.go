package probes

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var testLimits = Limits{
	MaxChecks:           6,
	DefaultCheckTimeout: 5 * time.Second,
	MaxCheckTimeout:     10 * time.Second,
	MaxJobDuration:      90 * time.Second,
	MaxOutputBytes:      64 << 10,
}

func testPolicy() DestinationPolicy {
	return DestinationPolicy{
		AllowCIDRs:            []string{"10.0.0.0/8"},
		AllowHostnameSuffixes: []string{".svc.cluster.local"},
		AllowPorts:            []PortRange{{From: 80, To: 443}, {From: 8080, To: 8443}},
	}.WithBuiltinDenies()
}

func codes(err error) map[string]bool {
	out := map[string]bool{}
	var ve ValidationErrors
	if errors.As(err, &ve) {
		for _, e := range ve {
			out[e.Code] = true
		}
	}
	return out
}

func TestBuildSpecAllMethodsWithPerCheckPorts(t *testing.T) {
	req := RunRequest{
		Namespace: "payments",
		Target:    "api.payments.svc.cluster.local",
		Checks: []CheckRequest{
			{Method: MethodDNS},
			{Method: MethodTCP, Port: 8443},
			{Method: MethodHTTP},
			{Method: MethodHTTPS, HTTP: &HTTPOptions{Method: "HEAD", Path: "/health"}},
			{Method: MethodPing},
			{Method: MethodTraceroute, Traceroute: &TracerouteOptions{MaxHops: 15}},
		},
	}
	spec, err := BuildSpec("abcdef0123456789", req, testPolicy(), testLimits)
	if err != nil {
		t.Fatalf("BuildSpec: %v", err)
	}
	ports := map[Method]int{}
	for _, c := range spec.Checks {
		ports[c.Method] = c.Port
	}
	want := map[Method]int{MethodDNS: 0, MethodTCP: 8443, MethodHTTP: 80, MethodHTTPS: 443, MethodPing: 0, MethodTraceroute: 0}
	for m, p := range want {
		if ports[m] != p {
			t.Errorf("%s port = %d, want %d", m, ports[m], p)
		}
	}
	if h := spec.Checks[3].HTTP; h.Method != "HEAD" || h.Path != "/health" {
		t.Errorf("https options = %+v", h)
	}
	if spec.Checks[4].Ping.Count != DefaultPingCount || spec.Checks[4].TimeoutMS != 5000 {
		t.Errorf("ping = %+v", spec.Checks[4])
	}
	if spec.Checks[5].TimeoutMS != 16000 {
		t.Errorf("traceroute timeout = %d", spec.Checks[5].TimeoutMS)
	}
	b, _ := json.Marshal(spec)
	var back Spec
	if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
		t.Fatalf("round trip validate: %v %v", err, back.Validate())
	}
}

func TestBuildSpecValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		req  RunRequest
		code string
	}{
		{"no checks", RunRequest{Target: "10.0.0.1"}, "required"},
		{"unknown method", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: "nmap"}}}, "unknown_method"},
		{"shell method", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: "sh -c id"}}}, "unknown_method"},
		{"duplicate", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodPing}, {Method: MethodPing}}}, "duplicate_method"},
		{"dns on ip", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodDNS}}}, "hostname_required"},
		{"tcp without port", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP}}}, "port_required"},
		{"bad port", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP, Port: 70000}}}, "invalid_port"},
		{"port on ping", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodPing, Port: 80}}}, "port_not_applicable"},
		{"port on dns", RunRequest{Target: "a.svc.cluster.local", Checks: []CheckRequest{{Method: MethodDNS, Port: 53}}}, "port_not_applicable"},
		{"timeout too high", RunRequest{Target: "10.0.0.1", TimeoutSeconds: 30, Checks: []CheckRequest{{Method: MethodTCP, Port: 80}}}, "out_of_range"},
		{"http post", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodHTTP, HTTP: &HTTPOptions{Method: "POST"}}}}, "invalid_http_method"},
		{"bad path", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodHTTPS, HTTP: &HTTPOptions{Path: "/a b"}}}}, "invalid_path"},
		{"options mismatch", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP, Port: 80, HTTP: &HTTPOptions{}}}}, "unexpected_options"},
		{"ping count", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodPing, Ping: &PingOptions{Count: 50}}}}, "out_of_range"},
		{"hops", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTraceroute, Traceroute: &TracerouteOptions{MaxHops: 64}}}}, "out_of_range"},
		{"url target", RunRequest{Target: "https://10.0.0.1/", Checks: []CheckRequest{{Method: MethodHTTPS}}}, "url_not_supported"},
		{"flag target", RunRequest{Target: "-v", Checks: []CheckRequest{{Method: MethodTCP, Port: 80}}}, "flag_like"},
		{"bad family", RunRequest{Target: "a.svc.cluster.local", Checks: []CheckRequest{{Method: MethodDNS, DNS: &DNSOptions{Family: "any"}}}}, "invalid_family"},
		{"bad mode", RunRequest{Mode: "shell", Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP, Port: 80}}}, "invalid_mode"},
	}
	firewall := RunRequest{Mode: ModeFirewall, Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodPing}, {Method: MethodTraceroute},
		{Method: MethodTCP, Port: 443}, {Method: MethodHTTPS, Port: 443}}}
	if _, err := BuildSpec("abcdef0123456789", firewall, testPolicy(), testLimits); err != nil {
		t.Errorf("firewall mode: %v", err)
	}
	for _, c := range cases {
		_, err := BuildSpec("abcdef0123456789", c.req, testPolicy(), testLimits)
		if !codes(err)[c.code] {
			t.Errorf("%s: err = %v, want code %s", c.name, err, c.code)
		}
	}
}

func TestBuildSpecBudget(t *testing.T) {
	lim := testLimits
	lim.MaxJobDuration = 30 * time.Second
	req := RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTraceroute, Traceroute: &TracerouteOptions{MaxHops: 30}}}}
	if _, err := BuildSpec("abcdef0123456789", req, testPolicy(), lim); !codes(err)["budget_exceeded"] {
		t.Errorf("err = %v, want budget_exceeded", err)
	}
}

func TestBuildSpecPolicyDenied(t *testing.T) {
	cases := []RunRequest{
		{Target: "169.254.169.254", Checks: []CheckRequest{{Method: MethodHTTP}}},
		{Target: "[::ffff:169.254.169.254]", Checks: []CheckRequest{{Method: MethodPing}}},
		{Target: "192.168.1.1", Checks: []CheckRequest{{Method: MethodTraceroute}}},
		{Target: "evil.example.com", Checks: []CheckRequest{{Method: MethodTCP, Port: 80}}},
		{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP, Port: 22}}},
		// One allowed port does not authorise another check's denied port.
		{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodHTTP}, {Method: MethodTCP, Port: 6443}}},
	}
	for _, req := range cases {
		_, err := BuildSpec("abcdef0123456789", req, testPolicy(), testLimits)
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Errorf("%s %+v: err = %v, want DeniedError", req.Target, req.Checks, err)
		}
	}
}

func TestSpecValidateRejectsTampering(t *testing.T) {
	good, err := BuildSpec("abcdef0123456789", RunRequest{Target: "10.0.0.1", Checks: []CheckRequest{{Method: MethodTCP, Port: 80}, {Method: MethodPing}}}, testPolicy(), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Spec){
		"schema":      func(s *Spec) { s.SchemaVersion = "v0" },
		"runid":       func(s *Spec) { s.RunID = "../../etc" },
		"host swap":   func(s *Spec) { s.Target.Host = "169.254.169.254" },
		"method":      func(s *Spec) { s.Checks[0].Method = "exec" },
		"timeout":     func(s *Spec) { s.Checks[0].TimeoutMS = 600000 },
		"no port":     func(s *Spec) { s.Checks[0].Port = 0 },
		"ping port":   func(s *Spec) { s.Checks[1].Port = 80 },
		"ping count":  func(s *Spec) { s.Checks[1].Ping = &PingOptions{Count: 1000} },
		"output":      func(s *Spec) { s.MaxOutputBytes = 1 << 30 },
		"dup id":      func(s *Spec) { s.Checks = append(s.Checks, s.Checks[0]) },
		"bad policy":  func(s *Spec) { s.Policy.AllowCIDRs = []string{"x"} },
		"flag target": func(s *Spec) { s.Target.Raw = "-oProxyCommand=id" },
	}
	for name, m := range mutations {
		s := good
		s.Checks = append([]Check(nil), good.Checks...)
		s.Policy.AllowCIDRs = append([]string(nil), good.Policy.AllowCIDRs...)
		m(&s)
		if s.Validate() == nil {
			t.Errorf("%s: tampered spec accepted", name)
		}
	}
}

func TestBuildSpecUDPPortsAndProtocols(t *testing.T) {
	policy := DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []PortRange{{From: 1, To: 65535}}}.WithBuiltinDenies()
	build := func(c CheckRequest) (Spec, error) {
		return BuildSpec("abcdef0123456789", RunRequest{Namespace: "payments", Target: "10.1.2.3", Checks: []CheckRequest{c}}, policy, testLimits)
	}
	for proto, want := range map[string]int{UDPDNS: 53, UDPNTP: 123} {
		spec, err := build(CheckRequest{Method: MethodUDP, UDP: &UDPOptions{Protocol: proto}})
		if err != nil || spec.Checks[0].Port != want || spec.Checks[0].UDP.Protocol != proto {
			t.Errorf("%s: spec=%+v err=%v", proto, spec.Checks, err)
		}
	}
	if spec, err := build(CheckRequest{Method: MethodUDP, Port: 5353, UDP: &UDPOptions{Protocol: UDPDNS}}); err != nil || spec.Checks[0].Port != 5353 {
		t.Errorf("explicit DNS port: %+v %v", spec.Checks, err)
	}
	if spec, err := build(CheckRequest{Method: MethodUDP, Port: 514}); err != nil || spec.Checks[0].UDP.Protocol != UDPGeneric {
		t.Errorf("generic by default: %+v %v", spec.Checks, err)
	}
	if _, err := build(CheckRequest{Method: MethodUDP, UDP: &UDPOptions{Protocol: UDPGeneric}}); !codes(err)["port_required"] {
		t.Errorf("generic without port: %v", err)
	}
	if _, err := build(CheckRequest{Method: MethodUDP, Port: 53, UDP: &UDPOptions{Protocol: "snmp"}}); !codes(err)["invalid_udp_protocol"] {
		t.Errorf("unknown protocol: %v", err)
	}
	if _, err := build(CheckRequest{Method: MethodTCP, Port: 53, UDP: &UDPOptions{Protocol: UDPDNS}}); !codes(err)["unexpected_options"] {
		t.Errorf("udp options on tcp: %v", err)
	}
	// The destination policy applies to UDP ports too.
	narrow := DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []PortRange{{From: 443, To: 443}}}.WithBuiltinDenies()
	_, err := BuildSpec("abcdef0123456789", RunRequest{Namespace: "payments", Target: "10.1.2.3",
		Checks: []CheckRequest{{Method: MethodUDP, UDP: &UDPOptions{Protocol: UDPDNS}}}}, narrow, testLimits)
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Errorf("UDP port outside the policy: %v", err)
	}
}
