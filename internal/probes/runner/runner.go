// Package runner executes a validated probe spec inside the probe Pod using
// typed Go network primitives. It never spawns processes or shells.
package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

const (
	maxHTTPBodyRead = 4096
	maxHeaderBytes  = 64 << 10
	userAgent       = "netcheck-probe/1"
)

// Resolver is the subset of *net.Resolver used by the runner.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Dialer is the subset of *net.Dialer used by the runner.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Runner executes checks sequentially.
type Runner struct {
	Resolver Resolver
	Dialer   Dialer
	// ICMP opens unprivileged ICMP sockets for ping and traceroute.
	ICMP ICMPDialer
	// RootCAs overrides the system trust store (tests only). Nil = system.
	RootCAs *x509.CertPool
	// Logf receives human readable progress lines (written to stderr).
	Logf func(format string, args ...any)
}

// New returns a Runner using the Pod's own resolver configuration.
func New(logf func(string, ...any)) *Runner {
	return &Runner{
		Resolver: &net.Resolver{PreferGo: true},
		Dialer:   &net.Dialer{},
		ICMP:     dialICMP,
		Logf:     logf,
	}
}

func isDenied(err error) bool {
	var d *probes.DeniedError
	return errors.As(err, &d)
}

// Run executes every check of spec and returns the structured result.
func (r *Runner) Run(ctx context.Context, spec probes.Spec) probes.Result {
	res := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: spec.RunID}
	policy, err := spec.Policy.Compile()
	if err != nil {
		res.Error = "invalid policy: " + err.Error()
		return res
	}
	if spec.SettleMS > 0 {
		// Give the CNI time to program policies for this new Pod.
		r.logf("waiting %dms for network policy programming", spec.SettleMS)
		start := time.Now()
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(spec.SettleMS) * time.Millisecond):
		}
		res.SettledMS = int(time.Since(start).Milliseconds())
	}
	for _, c := range spec.Checks {
		res.Checks = append(res.Checks, r.runCheck(ctx, spec, policy, c))
	}
	return res
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

type checkState struct {
	out strings.Builder
}

func (s *checkState) printf(format string, args ...any) {
	fmt.Fprintf(&s.out, format+"\n", args...)
}

func (r *Runner) runCheck(parent context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check) probes.CheckResult {
	timeout := time.Duration(c.TimeoutMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cr := probes.CheckResult{ID: c.ID, Method: c.Method, Port: c.Port, StartedAt: time.Now().UTC()}
	st := &checkState{}
	var err error
	switch c.Method {
	case probes.MethodDNS:
		err = r.runDNS(ctx, spec, policy, c, &cr, st)
	case probes.MethodTCP:
		err = r.runTCP(ctx, spec, policy, c, &cr, st)
	case probes.MethodUDP:
		err = r.runUDP(ctx, spec, policy, c, &cr, st)
	case probes.MethodHTTP, probes.MethodHTTPS:
		err = r.runHTTP(ctx, spec, policy, c, &cr, st)
	case probes.MethodPing:
		err = r.runPing(ctx, spec, policy, c, &cr, st)
	case probes.MethodTraceroute:
		err = r.runTraceroute(ctx, spec, policy, c, &cr, st)
	default:
		err = fmt.Errorf("method %q not supported", c.Method)
	}
	cr.FinishedAt = time.Now().UTC()
	cr.DurationMS = cr.FinishedAt.Sub(cr.StartedAt).Milliseconds()

	if err != nil {
		if cr.Category == "" {
			cr.Category = diagnostics.Classify(err, isDenied)
		}
		cr.Error = Sanitize(err.Error())
		st.printf("error: %s", cr.Error)
	}
	if cr.Category == "" {
		cr.Category = diagnostics.CategoryOK
	}
	switch {
	case err == nil:
		cr.Status = probes.StatusSucceeded
	case cr.Category == diagnostics.CategoryTimeout || cr.Category == diagnostics.CategoryDNSTimeout || cr.Category == diagnostics.CategoryUDPNoReply ||
		cr.Category == diagnostics.CategoryProxyNoAnswer:
		cr.Status = probes.StatusTimedOut
	default:
		cr.Status = probes.StatusFailed
	}
	cr.Output, cr.Truncated = Truncate(Sanitize(st.out.String()), spec.MaxOutputBytes)
	r.logf("check %s (%s): %s/%s in %dms", c.ID, c.Method, cr.Status, cr.Category, cr.DurationMS)
	return cr
}

// resolve returns resolved and policy-allowed addresses for the target. A
// hostname is re-checked against the suffix allowlist before any query.
func (r *Runner) resolve(ctx context.Context, t probes.Target, family string, policy *probes.CompiledPolicy, cr *probes.CheckResult, st *checkState) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if t.IsIP {
		a, err := netip.ParseAddr(t.Host)
		if err != nil {
			return nil, err
		}
		addrs = []netip.Addr{a}
	} else {
		if err := policy.CheckHostname(t.Host); err != nil {
			return nil, err
		}
		var err error
		addrs, err = r.Resolver.LookupNetIP(ctx, family, t.Host)
		if err != nil {
			return nil, err
		}
		st.printf("resolved %s (%s) -> %s", t.Host, family, joinAddrs(addrs))
	}
	var allowed []netip.Addr
	for _, a := range addrs {
		cr.ResolvedIPs = append(cr.ResolvedIPs, a.Unmap().String())
		if err := policy.CheckIP(a); err != nil {
			cr.DeniedIPs = append(cr.DeniedIPs, a.Unmap().String())
			st.printf("policy: %v", err)
			continue
		}
		allowed = append(allowed, a.Unmap())
	}
	if len(addrs) == 0 {
		cr.Category = diagnostics.CategoryDNSNoAddress
		return nil, errors.New("no addresses returned for " + t.Host)
	}
	if len(allowed) == 0 {
		return nil, &probes.DeniedError{Reason: "all resolved addresses are denied by policy"}
	}
	return allowed, nil
}

func (r *Runner) runDNS(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	t := spec.Target
	family := c.DNS.Family
	cr.Equivalent = []string{"getent", map[string]string{"ip": "ahosts", "ip4": "ahostsv4", "ip6": "ahostsv6"}[family], t.Host}
	if err := policy.CheckHostname(t.Host); err != nil {
		return err
	}
	addrs, err := r.Resolver.LookupNetIP(ctx, family, t.Host)
	dns := &probes.DNSResult{Family: family}
	cr.DNS = dns
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		cr.Category = diagnostics.CategoryDNSNoAddress
		return errors.New("no addresses returned")
	}
	for _, a := range addrs {
		s := a.Unmap().String()
		dns.Addresses = append(dns.Addresses, s)
		cr.ResolvedIPs = append(cr.ResolvedIPs, s)
		if policy.CheckIP(a) != nil {
			cr.DeniedIPs = append(cr.DeniedIPs, s)
		}
	}
	st.printf("resolved %s (%s) -> %s", t.Host, family, strings.Join(dns.Addresses, ", "))
	if cname, err := r.Resolver.LookupCNAME(ctx, t.Host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != t.Host {
			dns.CNAME = cname
			st.printf("canonical name: %s", cname)
		}
	}
	return nil
}

func (r *Runner) runTCP(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	t := spec.Target
	if err := policy.CheckPort(c.Port); err != nil {
		return err
	}
	if c.Proxy != nil {
		// Through a proxy the destination is checked by name only: the proxy
		// resolves it and connects to it.
		if err := policy.CheckHost(t); err != nil {
			return err
		}
		cr.Equivalent = []string{"nc", "-z", "-v", "-w", strconv.Itoa(max(1, c.TimeoutMS/1000)), "-X", "connect", "-x", c.Proxy.Address(), t.Host, strconv.Itoa(c.Port)}
		conn, err := r.dialProxy(ctx, policy, *c.Proxy, cr, st)
		if err != nil {
			return err
		}
		defer conn.Close()
		return proxyTunnel(ctx, conn, net.JoinHostPort(t.Host, strconv.Itoa(c.Port)), cr, st)
	}
	allowed, err := r.resolve(ctx, t, "ip", policy, cr, st)
	if err != nil {
		return err
	}
	ip := allowed[0]
	cr.UsedIP = ip.String()
	cr.Equivalent = []string{"nc", "-z", "-v", "-w", strconv.Itoa(max(1, c.TimeoutMS/1000)), ip.String(), strconv.Itoa(c.Port)}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(c.Port))
	st.printf("connecting tcp %s", addr)
	conn, err := r.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	st.printf("connected %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
	return nil
}

func (r *Runner) runHTTP(ctx context.Context, spec probes.Spec, policy *probes.CompiledPolicy, c probes.Check, cr *probes.CheckResult, st *checkState) error {
	t := spec.Target
	opts := c.HTTP
	if err := policy.CheckPort(c.Port); err != nil {
		return err
	}
	scheme := string(c.Method) // "http" or "https"
	u := scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(c.Port)) + opts.Path
	cr.HTTP = &probes.HTTPResult{URL: u, Method: opts.Method}

	cr.Equivalent = []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}\\n", "--max-time", strconv.Itoa(max(1, c.TimeoutMS/1000)), "--max-redirs", "0"}
	if opts.Method == "HEAD" {
		cr.Equivalent = append(cr.Equivalent, "--head")
	}
	if opts.IgnoreTLSErrors {
		cr.Equivalent = append(cr.Equivalent, "--insecure")
	}

	// Never use environment proxies: only the proxy chosen for the check.
	var proxyURL func(*http.Request) (*url.URL, error)
	var dial func(ctx context.Context) (net.Conn, error)
	var connectStart time.Time
	pinned := ""
	if p := c.Proxy; p != nil {
		// The proxy resolves the destination; it is checked by name only.
		if err := policy.CheckHost(t); err != nil {
			return err
		}
		proxyURL = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: p.Address()}, nil }
		dial = func(ctx context.Context) (net.Conn, error) {
			conn, err := r.dialProxy(ctx, policy, *p, cr, st)
			connectStart = time.Now()
			return conn, err
		}
		cr.Equivalent = append(cr.Equivalent, "--proxy", "http://"+p.Address())
	} else {
		allowed, err := r.resolve(ctx, t, "ip", policy, cr, st)
		if err != nil {
			return err
		}
		ip := allowed[0]
		cr.UsedIP = ip.String()
		pinned = net.JoinHostPort(ip.String(), strconv.Itoa(c.Port))
		// Always dial the validated, pinned address (DNS rebinding defense).
		dial = func(ctx context.Context) (net.Conn, error) { return r.Dialer.DialContext(ctx, "tcp", pinned) }
		if !t.IsIP {
			cr.Equivalent = append(cr.Equivalent, "--resolve", fmt.Sprintf("%s:%d:%s", t.Host, c.Port, ip))
		}
	}
	cr.Equivalent = append(cr.Equivalent, "--", u)

	roots, extra, err := r.trustPool(spec.TrustedCAs)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy:       proxyURL,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
			recordConnect(cr.Proxy, resp, time.Since(connectStart))
			st.printf("CONNECT %s: proxy answered %s", net.JoinHostPort(t.Host, strconv.Itoa(c.Port)), cr.Proxy.StatusText)
			if resp.StatusCode/100 != 2 {
				cr.Category = proxyStatusCategory(resp.StatusCode)
			}
			return nil
		},
		// The certificate is checked by inspectCertificate, which reports
		// every problem; the handshake fails on them unless they are ignored.
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				rep := inspectCertificate(cs.PeerCertificates, t.Host, roots, extra, time.Now())
				h := cr.HTTP
				h.TLSNames, h.TLSIssuer = rep.names, rep.issuer
				h.TLSTrustedCA, _ = Truncate(Sanitize(rep.trustedCA), 256)
				if rep.trustedCA != "" {
					st.printf("certificate trusted through the configured authority %s", h.TLSTrustedCA)
					// curl must be given the same authorities to reproduce it.
					cr.Equivalent = slices.Insert(cr.Equivalent, len(cr.Equivalent)-2, "--cacert", "netcheck-trusted-cas.pem")
				}
				if len(rep.problems) == 0 {
					return nil
				}
				h.TLSProblems, h.TLSProblemDetail = rep.problems, rep.detail
				if opts.IgnoreTLSErrors {
					h.TLSIgnored = true
					st.printf("certificate problems ignored as requested: %s", rep.detail)
					return nil
				}
				return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: errors.New(rep.detail)}
			}},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
	}

	var start, connectDone, tlsStart, tlsDone, firstByte time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { start = time.Now() },
		ConnectDone:          func(string, string, error) { connectDone = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), opts.Method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if c.Proxy != nil {
		st.printf("%s %s (through proxy %s)", opts.Method, u, c.Proxy.Name)
	} else {
		st.printf("%s %s (pinned to %s)", opts.Method, u, pinned)
	}

	resp, err := client.Do(req)
	h := cr.HTTP
	if !connectDone.IsZero() {
		h.ConnectMS = connectDone.Sub(start).Milliseconds()
	}
	if !tlsDone.IsZero() {
		h.TLSMS = tlsDone.Sub(tlsStart).Milliseconds()
	}
	if err != nil {
		switch {
		case cr.Category != "": // the proxy could not be reached or refused the tunnel
		case cr.Proxy != nil && cr.Proxy.Reached && cr.Proxy.Status == 0:
			cr.Category = noAnswerCategory(err)
		default:
			cat := diagnostics.Classify(err, isDenied)
			if cat == diagnostics.CategoryError && !connectDone.IsZero() {
				cat = diagnostics.CategoryHTTPProtocol
			}
			cr.Category = cat
		}
		return err
	}
	defer resp.Body.Close()
	if !firstByte.IsZero() {
		h.FirstByteMS = firstByte.Sub(start).Milliseconds()
	}
	h.StatusCode = resp.StatusCode
	h.Proto = resp.Proto
	if loc := resp.Header.Get("Location"); loc != "" {
		h.Location, _ = Truncate(Sanitize(loc), 512)
	}
	if resp.TLS != nil {
		h.TLSVersion = tls.VersionName(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			h.TLSPeerCN, _ = Truncate(Sanitize(leaf.Subject.CommonName), 256)
			h.TLSNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBodyRead+1))
	h.BodyBytes = min(n, maxHTTPBodyRead)
	h.BodyTruncated = n > maxHTTPBodyRead
	st.printf("response: %d %s", resp.StatusCode, Sanitize(resp.Proto))
	cr.Category = diagnostics.CategoryHTTPResponse
	return nil
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.Unmap().String()
	}
	return strings.Join(s, ", ")
}
