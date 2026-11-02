package runner

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// loopbackPolicy allows loopback ONLY for these tests; production policies
// always carry the builtin denies (see probes.WithBuiltinDenies).
func loopbackPolicy() probes.DestinationPolicy {
	return probes.DestinationPolicy{
		AllowCIDRs:            []string{"127.0.0.0/8", "10.0.0.0/8"},
		DenyCIDRs:             []string{"169.254.0.0/16"},
		AllowHostnameSuffixes: []string{".svc.cluster.local"},
		AllowPorts:            []probes.PortRange{{From: 1, To: 65535}},
	}
}

type fakeResolver struct {
	addrs map[string][]netip.Addr
	err   error
	cname string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs[host], nil
}

func (f *fakeResolver) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }

type countingDialer struct {
	inner Dialer
	calls atomic.Int32
	addrs []string
}

func (d *countingDialer) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	d.calls.Add(1)
	d.addrs = append(d.addrs, a)
	return d.inner.DialContext(ctx, n, a)
}

type blockingDialer struct{}

func (blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
}

func newRunner(res Resolver) (*Runner, *countingDialer) {
	d := &countingDialer{inner: &net.Dialer{}}
	if res == nil {
		res = &fakeResolver{}
	}
	return &Runner{Resolver: res, Dialer: d}, d
}

func mkSpec(t *testing.T, raw string, port int, checks ...probes.Check) probes.Spec {
	t.Helper()
	tgt, err := probes.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range checks {
		switch checks[i].Method {
		case probes.MethodTCP, probes.MethodUDP, probes.MethodHTTP, probes.MethodHTTPS:
			if checks[i].Port == 0 {
				checks[i].Port = port
			}
		}
		checks[i].ID = strconv.Itoa(i+1) + "-" + string(checks[i].Method)
		if checks[i].TimeoutMS == 0 {
			checks[i].TimeoutMS = 3000
		}
	}
	s := probes.Spec{SchemaVersion: probes.SchemaVersion, RunID: "abcdef0123456789", Target: tgt, Checks: checks,
		Policy: loopbackPolicy(), MaxOutputBytes: 64 << 10}
	if err := s.Validate(); err != nil {
		t.Fatalf("spec invalid: %v", err)
	}
	return s
}

func one(t *testing.T, r *Runner, s probes.Spec) probes.CheckResult {
	t.Helper()
	res := r.Run(context.Background(), s)
	if res.Error != "" || len(res.Checks) != 1 {
		t.Fatalf("run error %q, checks %d", res.Error, len(res.Checks))
	}
	return res.Checks[0]
}

func portOf(t *testing.T, addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTCPSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", portOf(t, ln.Addr().String()), probes.Check{Method: probes.MethodTCP}))
	if cr.Status != probes.StatusSucceeded || cr.Category != diagnostics.CategoryOK || cr.UsedIP != "127.0.0.1" {
		t.Fatalf("result = %+v", cr)
	}
	if len(cr.Equivalent) == 0 || cr.Equivalent[0] != "nc" {
		t.Errorf("equivalent argv = %v", cr.Equivalent)
	}
}

func TestTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, ln.Addr().String())
	ln.Close()
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, probes.Check{Method: probes.MethodTCP, TimeoutMS: 8000}))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryTCPRefused {
		t.Fatalf("result = %+v", cr)
	}
}

func TestTCPTimeoutIsTimedOut(t *testing.T) {
	r := &Runner{Resolver: &fakeResolver{}, Dialer: blockingDialer{}}
	cr := one(t, r, mkSpec(t, "10.1.2.3", 443, probes.Check{Method: probes.MethodTCP, TimeoutMS: 150}))
	if cr.Status != probes.StatusTimedOut || cr.Category != diagnostics.CategoryTimeout {
		t.Fatalf("result = %+v", cr)
	}
}

func TestPolicyDeniedNeverDials(t *testing.T) {
	r, d := newRunner(nil)
	s := mkSpec(t, "169.254.169.254", 80, probes.Check{Method: probes.MethodTCP}, httpCheck("GET", "http", "/latest/meta-data/"))
	res := r.Run(context.Background(), s)
	for _, cr := range res.Checks {
		if cr.Category != diagnostics.CategoryDestinationDenied || cr.Status != probes.StatusFailed {
			t.Errorf("check %s = %+v", cr.ID, cr)
		}
	}
	if d.calls.Load() != 0 {
		t.Fatalf("dialer called %d times for a denied destination", d.calls.Load())
	}
}

func TestDNSRebindingIsBlocked(t *testing.T) {
	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"evil.svc.cluster.local": {netip.MustParseAddr("169.254.169.254")},
	}}
	r, d := newRunner(res)
	cr := one(t, r, mkSpec(t, "evil.svc.cluster.local", 80, httpCheck("GET", "http", "/")))
	if cr.Category != diagnostics.CategoryDestinationDenied || d.calls.Load() != 0 {
		t.Fatalf("result = %+v, dials = %d", cr, d.calls.Load())
	}
	if len(cr.DeniedIPs) != 1 || cr.DeniedIPs[0] != "169.254.169.254" {
		t.Errorf("denied ips = %v", cr.DeniedIPs)
	}
}

func TestMixedResolutionDialsOnlyAllowedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"mixed.svc.cluster.local": {netip.MustParseAddr("::ffff:169.254.169.254"), netip.MustParseAddr("127.0.0.1")},
	}}
	r, d := newRunner(res)
	cr := one(t, r, mkSpec(t, "mixed.svc.cluster.local", portOf(t, ln.Addr().String()), probes.Check{Method: probes.MethodTCP}))
	if cr.Status != probes.StatusSucceeded || cr.UsedIP != "127.0.0.1" {
		t.Fatalf("result = %+v", cr)
	}
	if len(d.addrs) != 1 || d.addrs[0] != ln.Addr().String() {
		t.Fatalf("dialed %v", d.addrs)
	}
}

func TestHostnameOutsideSuffixIsNotResolved(t *testing.T) {
	res := &fakeResolver{addrs: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("10.0.0.1")}}}
	r, d := newRunner(res)
	cr := one(t, r, mkSpec(t, "example.com", 443, probes.Check{Method: probes.MethodTCP}))
	if cr.Category != diagnostics.CategoryDestinationDenied || d.calls.Load() != 0 || len(cr.ResolvedIPs) != 0 {
		t.Fatalf("result = %+v", cr)
	}
}

func TestDNSResults(t *testing.T) {
	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"api.svc.cluster.local": {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("169.254.1.1")},
	}, cname: "api-backend.svc.cluster.local."}
	r, _ := newRunner(res)
	cr := one(t, r, mkSpec(t, "api.svc.cluster.local", 0, probes.Check{Method: probes.MethodDNS, DNS: &probes.DNSOptions{Family: "ip4"}}))
	if cr.Status != probes.StatusSucceeded || len(cr.DNS.Addresses) != 2 || cr.DNS.CNAME != "api-backend.svc.cluster.local" {
		t.Fatalf("result = %+v dns=%+v", cr, cr.DNS)
	}
	if len(cr.DeniedIPs) != 1 {
		t.Errorf("denied ips should flag the link-local address: %v", cr.DeniedIPs)
	}
	if cr.Equivalent[1] != "ahostsv4" {
		t.Errorf("equivalent = %v", cr.Equivalent)
	}

	r2, _ := newRunner(&fakeResolver{err: &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}})
	cr = one(t, r2, mkSpec(t, "nope.svc.cluster.local", 0, probes.Check{Method: probes.MethodDNS, DNS: &probes.DNSOptions{Family: "ip"}}))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryDNSNXDomain {
		t.Fatalf("nxdomain result = %+v", cr)
	}

	r3, _ := newRunner(&fakeResolver{addrs: map[string][]netip.Addr{}})
	cr = one(t, r3, mkSpec(t, "empty.svc.cluster.local", 0, probes.Check{Method: probes.MethodDNS, DNS: &probes.DNSOptions{Family: "ip6"}}))
	if cr.Category != diagnostics.CategoryDNSNoAddress {
		t.Fatalf("no address result = %+v", cr)
	}
}

func httpCheck(method, scheme, path string) probes.Check {
	return probes.Check{Method: probes.Method(scheme), HTTP: &probes.HTTPOptions{Method: method, Path: path}}
}

func TestHTTP404IsConnectivitySuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("probe must not send Authorization")
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", portOf(t, u.Host), httpCheck("GET", "http", "/missing")))
	if cr.Status != probes.StatusSucceeded || cr.Category != diagnostics.CategoryHTTPResponse || cr.HTTP.StatusCode != 404 {
		t.Fatalf("result = %+v http=%+v", cr, cr.HTTP)
	}
}

func TestHTTPRedirectNotFollowed(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", http.StatusFound)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", portOf(t, u.Host), httpCheck("GET", "http", "/")))
	if cr.HTTP.StatusCode != 302 || cr.HTTP.Location == "" || followed.Load() {
		t.Fatalf("redirect handling wrong: %+v followed=%v", cr.HTTP, followed.Load())
	}
}

func TestHTTPPinsResolvedIPAndKeepsHost(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotHost = r.Host }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port := portOf(t, u.Host)
	res := &fakeResolver{addrs: map[string][]netip.Addr{"web.svc.cluster.local": {netip.MustParseAddr("127.0.0.1")}}}
	r, d := newRunner(res)
	cr := one(t, r, mkSpec(t, "web.svc.cluster.local", port, httpCheck("HEAD", "http", "/")))
	if cr.Status != probes.StatusSucceeded || cr.HTTP.StatusCode != 200 {
		t.Fatalf("result = %+v", cr)
	}
	if gotHost != "web.svc.cluster.local:"+strconv.Itoa(port) {
		t.Errorf("Host header = %q", gotHost)
	}
	if len(d.addrs) != 1 || d.addrs[0] != "127.0.0.1:"+strconv.Itoa(port) {
		t.Errorf("dialed %v", d.addrs)
	}
}

func TestHTTPSCertificateValidation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port := portOf(t, u.Host)

	r, _ := newRunner(nil) // system roots: the test certificate is untrusted
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, httpCheck("GET", "https", "/")))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryTLSCert {
		t.Fatalf("untrusted cert result = %+v", cr)
	}

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r2, _ := newRunner(nil)
	r2.RootCAs = pool
	cr = one(t, r2, mkSpec(t, "127.0.0.1", port, httpCheck("GET", "https", "/")))
	if cr.Status != probes.StatusSucceeded || cr.HTTP.TLSVersion == "" || cr.HTTP.TLSNotAfter == "" {
		t.Fatalf("trusted cert result = %+v http=%+v", cr, cr.HTTP)
	}
}

func TestHTTPNonHTTPServerIsProtocolError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n\x1b[31mjunk\r\n\r\n"))
		time.Sleep(100 * time.Millisecond)
		c.Close()
	}()
	r, _ := newRunner(nil)
	cr := one(t, r, mkSpec(t, "127.0.0.1", portOf(t, ln.Addr().String()), httpCheck("GET", "http", "/")))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryHTTPProtocol {
		t.Fatalf("result = %+v", cr)
	}
}

func TestSettleDelayIsRecorded(t *testing.T) {
	r := &Runner{Resolver: &fakeResolver{}, Dialer: blockingDialer{}}
	s := mkSpec(t, "10.0.0.1", 80, probes.Check{Method: probes.MethodTCP, TimeoutMS: 100})
	s.SettleMS = 60
	res := r.Run(context.Background(), s)
	if res.SettledMS < 50 {
		t.Fatalf("settled %dms, want >= 50", res.SettledMS)
	}
}

func TestOutputIsTruncated(t *testing.T) {
	r := &Runner{Resolver: &fakeResolver{}, Dialer: blockingDialer{}}
	s := mkSpec(t, "10.0.0.1", 80, probes.Check{Method: probes.MethodTCP, TimeoutMS: 100})
	s.MaxOutputBytes = 10
	cr := one(t, r, s)
	if !cr.Truncated || len(cr.Output) > 10 {
		t.Fatalf("output not truncated: %q", cr.Output)
	}
}
