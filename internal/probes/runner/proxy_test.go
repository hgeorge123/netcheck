package runner

import (
	"bufio"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

// testProxy is an HTTP proxy on 127.0.0.1 that answers CONNECT with
// behaviour: "tunnel" (200 and relays to the requested host), "silent" (never
// answers), "garbage" (not HTTP) or an HTTP status line such as "403 Forbidden".
func testProxy(t *testing.T, behaviour string) *probes.Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveProxy(conn, behaviour)
		}
	}()
	return &probes.Proxy{Name: "corp", Host: "127.0.0.1", Port: portOf(t, ln.Addr().String())}
}

func serveProxy(conn net.Conn, behaviour string) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		serveForward(conn, req, behaviour)
		return
	}
	switch behaviour {
	case "silent":
		time.Sleep(5 * time.Second)
	case "garbage":
		io.WriteString(conn, "hello there\r\n\r\n")
	case "tunnel":
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		go io.Copy(up, br)
		io.Copy(conn, up)
	default:
		io.WriteString(conn, "HTTP/1.1 "+behaviour+"\r\nContent-Length: 0\r\n\r\n")
	}
}

// serveForward handles a plain HTTP request sent to the proxy with an
// absolute URL: "tunnel" forwards it like a proxy (adding Via), "squid-403"
// answers the error page of a proxy that denies the destination.
func serveForward(conn net.Conn, req *http.Request, behaviour string) {
	switch behaviour {
	case "tunnel":
		if !req.URL.IsAbs() {
			io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			return
		}
		req.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nX-Squid-Error: ERR_CONNECT_FAIL 111\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer resp.Body.Close()
		resp.Header.Set("Via", "1.1 test-proxy")
		resp.Write(conn)
	case "squid-403":
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\nContent-Length: 0\r\n\r\n")
	default:
		io.WriteString(conn, "HTTP/1.1 "+behaviour+"\r\nContent-Length: 0\r\n\r\n")
	}
}

func viaProxy(c probes.Check, p *probes.Proxy) probes.Check {
	c.Proxy = p
	return c
}

func TestTCPThroughProxy(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
	port := portOf(t, ln.Addr().String())
	r, _ := newRunner(nil)

	p := testProxy(t, "tunnel")
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(probes.Check{Method: probes.MethodTCP}, p)))
	if cr.Status != probes.StatusSucceeded || cr.Proxy == nil || !cr.Proxy.Reached || cr.Proxy.Status != 200 ||
		cr.Proxy.UsedIP != "127.0.0.1" || cr.UsedIP != "" || !slices.Contains(cr.Equivalent, "connect") {
		t.Fatalf("tunnel = %+v proxy = %+v", cr, cr.Proxy)
	}

	for behaviour, want := range map[string]string{
		"403 Forbidden":                     diagnostics.CategoryProxyDenied,
		"407 Proxy Authentication Required": diagnostics.CategoryProxyAuthRequired,
		"502 Bad Gateway":                   diagnostics.CategoryProxyUpstreamFail,
		"garbage":                           diagnostics.CategoryProxyProtocolError,
	} {
		p := testProxy(t, behaviour)
		cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(probes.Check{Method: probes.MethodTCP}, p)))
		if cr.Status != probes.StatusFailed || cr.Category != want || !cr.Proxy.Reached {
			t.Errorf("%s: %s/%s proxy=%+v err=%s", behaviour, cr.Status, cr.Category, cr.Proxy, cr.Error)
		}
	}
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(probes.Check{Method: probes.MethodTCP}, testProxy(t, "403 Forbidden")))); cr.Proxy.Status != 403 ||
		!strings.Contains(cr.Error, `answered "403 Forbidden"`) {
		t.Errorf("403 evidence = %+v %q", cr.Proxy, cr.Error)
	}

	// The proxy accepts the connection but never answers: still waiting.
	c := viaProxy(probes.Check{Method: probes.MethodTCP, TimeoutMS: 500}, testProxy(t, "silent"))
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, c)); cr.Status != probes.StatusTimedOut || cr.Category != diagnostics.CategoryProxyNoAnswer {
		t.Errorf("silent proxy: %s/%s", cr.Status, cr.Category)
	}

	// Nothing listens at the proxy address.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	gone := &probes.Proxy{Name: "gone", Host: "127.0.0.1", Port: portOf(t, closed.Addr().String())}
	closed.Close()
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(probes.Check{Method: probes.MethodTCP}, gone))); cr.Category != diagnostics.CategoryProxyUnreachable ||
		cr.Proxy.Reached || !strings.Contains(cr.Error, "proxy gone") {
		t.Errorf("unreachable proxy: %s %+v %q", cr.Category, cr.Proxy, cr.Error)
	}

	// The proxy is a destination too: the policy applies to it.
	denied := &probes.Proxy{Name: "meta", Host: "169.254.169.254", Port: 80}
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(probes.Check{Method: probes.MethodTCP}, denied))); cr.Category != diagnostics.CategoryDestinationDenied {
		t.Errorf("denied proxy: %s %q", cr.Category, cr.Error)
	}
}

func TestHTTPSThroughProxy(t *testing.T) {
	ca := newCA(t, "Corp Root")
	now := time.Now()
	port := tlsServer(t, &ca, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r, _ := newRunner(nil)
	r.RootCAs = pool

	cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "https", "/"), testProxy(t, "tunnel"))))
	if cr.Status != probes.StatusSucceeded || cr.HTTP.StatusCode != http.StatusOK || cr.Proxy == nil || cr.Proxy.Status != 200 ||
		cr.UsedIP != "" || !slices.Contains(cr.Equivalent, "--proxy") || slices.Contains(cr.Equivalent, "--resolve") {
		t.Fatalf("https through proxy = %+v proxy = %+v http = %+v", cr, cr.Proxy, cr.HTTP)
	}
	if !strings.Contains(cr.Output, "through proxy corp") {
		t.Errorf("output = %q", cr.Output)
	}

	cr = one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "https", "/"), testProxy(t, "403 Forbidden"))))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryProxyDenied || cr.Proxy.Status != 403 || cr.HTTP.StatusCode != 0 {
		t.Errorf("https 403 = %s/%s proxy = %+v", cr.Status, cr.Category, cr.Proxy)
	}

	c := viaProxy(httpCheck("GET", "https", "/"), testProxy(t, "silent"))
	c.TimeoutMS = 500
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, c)); cr.Category != diagnostics.CategoryProxyNoAnswer {
		t.Errorf("https silent proxy: %s %q", cr.Category, cr.Error)
	}

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	gone := &probes.Proxy{Name: "gone", Host: "127.0.0.1", Port: portOf(t, closed.Addr().String())}
	closed.Close()
	if cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "https", "/"), gone))); cr.Category != diagnostics.CategoryProxyUnreachable {
		t.Errorf("https unreachable proxy: %s %q", cr.Category, cr.Error)
	}
}

func TestHTTPThroughProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer origin.Close()
	port := portOf(t, strings.TrimPrefix(origin.URL, "http://"))
	r, _ := newRunner(nil)

	// The proxy forwards the request: the answer is the destination's (404).
	p := testProxy(t, "tunnel")
	p.Personal = true
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "http", "/x"), p)))
	if cr.Status != probes.StatusSucceeded || cr.Category != diagnostics.CategoryHTTPResponse || cr.HTTP.StatusCode != http.StatusNotFound ||
		cr.Proxy == nil || cr.Proxy.Mode != probes.ProxyModeForward || cr.Proxy.Via != "1.1 test-proxy" || cr.Proxy.Status != 0 ||
		!cr.Proxy.Personal || cr.UsedIP != "" || !slices.Contains(cr.Equivalent, "--proxy") {
		t.Fatalf("forwarded = %+v proxy = %+v http = %+v", cr, cr.Proxy, cr.HTTP)
	}

	// Errors the proxy answers itself are proxy results.
	for behaviour, want := range map[string]string{
		"squid-403":                         diagnostics.CategoryProxyDenied,
		"407 Proxy Authentication Required": diagnostics.CategoryProxyAuthRequired,
	} {
		cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "http", "/"), testProxy(t, behaviour))))
		if cr.Status != probes.StatusFailed || cr.Category != want || cr.Proxy.Status == 0 {
			t.Errorf("%s: %s/%s proxy=%+v", behaviour, cr.Status, cr.Category, cr.Proxy)
		}
	}
	// A 403 without proxy markers is the destination's own answer.
	cr = one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "http", "/"), testProxy(t, "403 Forbidden"))))
	if cr.Category != diagnostics.CategoryHTTPResponse || cr.HTTP.StatusCode != http.StatusForbidden {
		t.Errorf("plain 403 = %s %+v", cr.Category, cr.HTTP)
	}
}

func TestProxyAuthorityOnlyThroughThatProxy(t *testing.T) {
	inspect := newCA(t, "Inspection CA")
	now := time.Now()
	port := tlsServer(t, &inspect, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	r, _ := newRunner(nil)
	r.RootCAs = x509.NewCertPool()

	p := testProxy(t, "tunnel")
	p.TrustedCAs = []string{pemOf(inspect.cert)}
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "https", "/"), p)))
	if cr.Status != probes.StatusSucceeded || cr.HTTP.TLSTrustedCA != "Inspection CA" {
		t.Fatalf("through the proxy = %+v http = %+v", cr, cr.HTTP)
	}
	// Direct, the authority of the proxy does not count.
	cr = one(t, r, mkSpec(t, "127.0.0.1", port, httpCheck("GET", "https", "/")))
	if cr.Status != probes.StatusFailed || !slices.Equal(cr.HTTP.TLSProblems, []string{probes.TLSUnknownAuthority}) {
		t.Fatalf("direct = %+v http = %+v", cr, cr.HTTP)
	}
	// The same authority globally and on the proxy is fine.
	spec := mkSpec(t, "127.0.0.1", port, viaProxy(httpCheck("GET", "https", "/"), p))
	spec.TrustedCAs = []string{pemOf(inspect.cert)}
	if cr := one(t, r, spec); cr.Status != probes.StatusSucceeded {
		t.Errorf("duplicate authority = %+v", cr)
	}
}
