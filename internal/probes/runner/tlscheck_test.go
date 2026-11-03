package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t *testing.T, name string) testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, key}
}

// leaf issues a server certificate; with ca nil it is self-signed.
func leaf(t *testing.T, ca *testCA, names []string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, NotBefore: notBefore, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func TestInspectCertificate(t *testing.T) {
	trusted := newCA(t, "Corp Root")
	other := newCA(t, "Unknown Root")
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)
	now := time.Now()
	valid := func() (time.Time, time.Time) { return now.Add(-time.Hour), now.Add(time.Hour) }
	nb, na := valid()

	cases := []struct {
		name     string
		cert     *x509.Certificate
		host     string
		want     []string
		fragment string
	}{
		{"valid", must(leaf(t, &trusted, []string{"api.example.com"}, nb, na)), "api.example.com", nil, ""},
		{"valid for an IP", must(leaf(t, &trusted, []string{"10.0.0.5"}, nb, na)), "10.0.0.5", nil, ""},
		{"expired", must(leaf(t, &trusted, []string{"api.example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))), "api.example.com",
			[]string{probes.TLSExpired}, "the certificate expired on"},
		{"not yet valid", must(leaf(t, &trusted, []string{"api.example.com"}, now.Add(24*time.Hour), now.Add(48*time.Hour))), "api.example.com",
			[]string{probes.TLSNotYetValid}, "is not valid until"},
		{"other host", must(leaf(t, &trusted, []string{"www.example.com", "example.com"}, nb, na)), "api.example.com",
			[]string{probes.TLSHostnameMismatch}, "does not cover api.example.com: it is for www.example.com, example.com"},
		{"unknown authority", must(leaf(t, &other, []string{"api.example.com"}, nb, na)), "api.example.com",
			[]string{probes.TLSUnknownAuthority}, "signed by Unknown Root, an authority the probe does not trust"},
		{"self-signed", must(leaf(t, nil, []string{"api.example.com"}, nb, na)), "api.example.com",
			[]string{probes.TLSSelfSigned}, "self-signed"},
		{"every problem at once", must(leaf(t, &other, []string{"old.example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))), "api.example.com",
			[]string{probes.TLSExpired, probes.TLSHostnameMismatch, probes.TLSUnknownAuthority}, "expired on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := inspectCertificate([]*x509.Certificate{tc.cert}, tc.host, roots, nil, now)
			if !slices.Equal(rep.problems, tc.want) || !strings.Contains(rep.detail, tc.fragment) {
				t.Fatalf("problems = %v, detail = %q", rep.problems, rep.detail)
			}
		})
	}
	if rep := inspectCertificate(nil, "x", roots, nil, now); !slices.Equal(rep.problems, []string{probes.TLSInvalid}) {
		t.Errorf("no certificate: %+v", rep)
	}
}

func must(c *x509.Certificate, _ *ecdsa.PrivateKey) *x509.Certificate { return c }

// tlsServer serves HTTPS on 127.0.0.1 with a certificate for names.
func tlsServer(t *testing.T, ca *testCA, names []string, notBefore, notAfter time.Time) int {
	t.Helper()
	c, key := leaf(t, ca, names, notBefore, notAfter)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return portOf(t, u.Host)
}

func TestHTTPSCertificateProblems(t *testing.T) {
	ca := newCA(t, "Corp Root")
	now := time.Now()
	port := tlsServer(t, &ca, []string{"other.example.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour)) // expired and for another name

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r, _ := newRunner(nil)
	r.RootCAs = pool

	// Default: the check fails and says exactly why.
	cr := one(t, r, mkSpec(t, "127.0.0.1", port, httpCheck("GET", "https", "/")))
	if cr.Status != probes.StatusFailed || cr.Category != diagnostics.CategoryTLSCert ||
		!slices.Equal(cr.HTTP.TLSProblems, []string{probes.TLSExpired, probes.TLSHostnameMismatch}) || cr.HTTP.TLSIgnored ||
		!strings.Contains(cr.Error, "does not cover 127.0.0.1") || cr.HTTP.StatusCode != 0 {
		t.Fatalf("result = %+v http = %+v", cr, cr.HTTP)
	}

	// Ignoring the errors: the request completes, the problems stay visible.
	c := httpCheck("GET", "https", "/")
	c.HTTP.IgnoreTLSErrors = true
	cr = one(t, r, mkSpec(t, "127.0.0.1", port, c))
	if cr.Status != probes.StatusSucceeded || cr.HTTP.StatusCode != http.StatusOK || !cr.HTTP.TLSIgnored ||
		!slices.Equal(cr.HTTP.TLSProblems, []string{probes.TLSExpired, probes.TLSHostnameMismatch}) ||
		cr.HTTP.TLSIssuer != "Corp Root" || !slices.Contains(cr.HTTP.TLSNames, "other.example.com") {
		t.Fatalf("ignored result = %+v http = %+v", cr, cr.HTTP)
	}
	if !slices.Contains(cr.Equivalent, "--insecure") {
		t.Errorf("equivalent command = %v", cr.Equivalent)
	}

	// A valid certificate reports no problem, ignored or not.
	okPort := tlsServer(t, &ca, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	cr = one(t, r, mkSpec(t, "127.0.0.1", okPort, c))
	if cr.Status != probes.StatusSucceeded || len(cr.HTTP.TLSProblems) != 0 || cr.HTTP.TLSIgnored {
		t.Fatalf("valid certificate = %+v http = %+v", cr, cr.HTTP)
	}
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func TestHTTPSConfiguredAuthority(t *testing.T) {
	public := newCA(t, "Public Root")
	corp := newCA(t, "Corp Inspection CA")
	now := time.Now()
	pool := x509.NewCertPool()
	pool.AddCert(public.cert)
	r, _ := newRunner(nil)
	r.RootCAs = pool

	// A certificate from the corporate authority (a proxy inspecting TLS)
	// is untrusted until the authority is configured.
	corpPort := tlsServer(t, &corp, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	cr := one(t, r, mkSpec(t, "127.0.0.1", corpPort, httpCheck("GET", "https", "/")))
	if cr.Status != probes.StatusFailed || !slices.Equal(cr.HTTP.TLSProblems, []string{probes.TLSUnknownAuthority}) {
		t.Fatalf("without the authority = %+v http = %+v", cr, cr.HTTP)
	}

	spec := mkSpec(t, "127.0.0.1", corpPort, httpCheck("GET", "https", "/"))
	spec.TrustedCAs = []string{pemOf(corp.cert)}
	cr = one(t, r, spec)
	if cr.Status != probes.StatusSucceeded || len(cr.HTTP.TLSProblems) != 0 || cr.HTTP.TLSTrustedCA != "Corp Inspection CA" {
		t.Fatalf("with the authority = %+v http = %+v", cr, cr.HTTP)
	}
	n := len(cr.Equivalent)
	if n < 4 || cr.Equivalent[n-4] != "--cacert" || cr.Equivalent[n-2] != "--" || !strings.HasPrefix(cr.Equivalent[n-1], "https://") {
		t.Errorf("equivalent command = %v", cr.Equivalent)
	}
	if !strings.Contains(cr.Output, "configured authority Corp Inspection CA") {
		t.Errorf("output = %q", cr.Output)
	}

	// The public authorities stay trusted, and are not reported as configured.
	publicPort := tlsServer(t, &public, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	spec = mkSpec(t, "127.0.0.1", publicPort, httpCheck("GET", "https", "/"))
	spec.TrustedCAs = []string{pemOf(corp.cert)}
	cr = one(t, r, spec)
	if cr.Status != probes.StatusSucceeded || cr.HTTP.TLSTrustedCA != "" || slices.Contains(cr.Equivalent, "--cacert") {
		t.Fatalf("public certificate = %+v http = %+v", cr, cr.HTTP)
	}
}
