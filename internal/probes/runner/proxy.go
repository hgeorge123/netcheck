package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// dialProxy connects to the proxy of a check. The proxy is a destination the
// Pod connects to, so its name is resolved and every address is checked
// against the policy like any target. Errors before the CONNECT mean the
// proxy could not be reached.
func (r *Runner) dialProxy(ctx context.Context, policy *probes.CompiledPolicy, p probes.Proxy, cr *probes.CheckResult, st *checkState) (net.Conn, error) {
	pr := &probes.ProxyResult{Name: p.Name, Address: p.Address()}
	cr.Proxy = pr
	unreachable := func(err error) error {
		if !isDenied(err) {
			cr.Category = diagnostics.CategoryProxyUnreachable
		}
		return fmt.Errorf("proxy %s (%s): %w", p.Name, p.Address(), err)
	}
	t, err := probes.ParseTarget(p.Host)
	if err != nil {
		return nil, unreachable(err)
	}
	if err := policy.CheckPort(p.Port); err != nil {
		return nil, unreachable(err)
	}
	var lookup probes.CheckResult
	allowed, err := r.resolve(ctx, t, "ip", policy, &lookup, st)
	pr.ResolvedIPs = lookup.ResolvedIPs
	if err != nil {
		return nil, unreachable(err)
	}
	pr.UsedIP = allowed[0].String()
	addr := net.JoinHostPort(pr.UsedIP, strconv.Itoa(p.Port))
	st.printf("connecting to proxy %s at %s", p.Name, addr)
	start := time.Now()
	conn, err := r.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, unreachable(err)
	}
	pr.Reached, pr.ConnectMS = true, time.Since(start).Milliseconds()
	st.printf("connected to proxy %s", p.Name)
	return conn, nil
}

// proxyTunnel asks the proxy for a CONNECT tunnel to dest (host:port) and
// returns nil when it answers 2xx. The proxy resolves dest itself.
func proxyTunnel(ctx context.Context, conn net.Conn, dest string, cr *probes.CheckResult, st *checkState) error {
	pr := cr.Proxy
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: dest}, Host: dest, Header: http.Header{"User-Agent": {userAgent}}}
	st.printf("CONNECT %s", dest)
	start := time.Now()
	resp, err := writeAndRead(conn, req)
	if err != nil {
		cr.Category = noAnswerCategory(err)
		return fmt.Errorf("proxy %s: no valid answer to CONNECT %s: %w", pr.Name, dest, err)
	}
	_ = resp.Body.Close()
	recordConnect(pr, resp, time.Since(start))
	st.printf("proxy answered %s", pr.StatusText)
	if resp.StatusCode/100 == 2 {
		return nil
	}
	cr.Category = proxyStatusCategory(resp.StatusCode)
	return fmt.Errorf("proxy %s answered %q to CONNECT %s", pr.Name, pr.StatusText, dest)
}

func writeAndRead(conn net.Conn, req *http.Request) (*http.Response, error) {
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), req)
}

func recordConnect(pr *probes.ProxyResult, resp *http.Response, took time.Duration) {
	pr.Status, pr.TunnelMS = resp.StatusCode, took.Milliseconds()
	pr.StatusText, _ = Truncate(Sanitize(resp.Status), 128)
}

// noAnswerCategory classifies a CONNECT without a valid reply: still waiting
// (the proxy is usually trying to reach the destination) or garbage.
func noAnswerCategory(err error) string {
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return diagnostics.CategoryProxyNoAnswer
	}
	return diagnostics.CategoryProxyProtocolError
}

// proxyStatusCategory maps a CONNECT reply that is not 2xx.
func proxyStatusCategory(code int) string {
	switch {
	case code == http.StatusProxyAuthRequired:
		return diagnostics.CategoryProxyAuthRequired
	case code >= 400 && code < 500:
		return diagnostics.CategoryProxyDenied
	case code >= 500:
		return diagnostics.CategoryProxyUpstreamFail
	}
	return diagnostics.CategoryProxyProtocolError
}
