package runner

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
)

// certReport is what the probe found when checking the server certificate.
type certReport struct {
	problems []string // probes.TLS* codes
	detail   string   // one sentence per problem, for people
	names    []string // DNS names and IP addresses of the certificate
	issuer   string
	// trustedCA is the configured authority (one of extra) the chain ends
	// at, when no public authority validates it.
	trustedCA string
}

// inspectCertificate checks the server certificate the way a browser would,
// but reports every problem instead of stopping at the first: validity
// dates, the host name and the chain of trust are checked independently.
// extra are the trusted authorities configured in NetCheck, already in roots.
func inspectCertificate(certs []*x509.Certificate, host string, roots *x509.CertPool, extra []*x509.Certificate, now time.Time) certReport {
	if len(certs) == 0 {
		return certReport{problems: []string{probes.TLSInvalid}, detail: "the server sent no certificate"}
	}
	leaf := certs[0]
	r := certReport{issuer: leaf.Issuer.CommonName}
	if r.issuer == "" {
		r.issuer = leaf.Issuer.String()
	}
	r.names = append(r.names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		r.names = append(r.names, ip.String())
	}
	if len(r.names) > 20 {
		r.names = r.names[:20]
	}
	var parts []string
	add := func(code, format string, a ...any) {
		r.problems = append(r.problems, code)
		parts = append(parts, fmt.Sprintf(format, a...))
	}

	switch {
	case now.After(leaf.NotAfter):
		add(probes.TLSExpired, "the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(leaf.NotBefore):
		add(probes.TLSNotYetValid, "the certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		covers := strings.Join(r.names, ", ")
		if covers == "" {
			covers = "no names (only CN " + leaf.Subject.CommonName + ")"
		}
		add(probes.TLSHostnameMismatch, "the certificate does not cover %s: it is for %s", host, covers)
	}
	// Trust is checked at a moment the certificate was valid, so an expired
	// certificate from a trusted authority is reported only as expired.
	at := now
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter.Add(-time.Minute)
	} else if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore.Add(time.Minute)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at})
	if err == nil {
		r.trustedCA = configuredAuthority(chains, extra)
	} else {
		var unknown x509.UnknownAuthorityError
		switch {
		case errors.As(err, &unknown) && selfSigned(leaf):
			add(probes.TLSSelfSigned, "the certificate is self-signed")
		case errors.As(err, &unknown):
			add(probes.TLSUnknownAuthority, "the certificate is signed by %s, an authority the probe does not trust", r.issuer)
		default:
			add(probes.TLSInvalid, "the certificate chain is not valid: %v", err)
		}
	}
	r.detail = strings.Join(parts, "; ")
	return r
}

// trustPool returns the roots for HTTPS: the public ones (r.RootCAs in
// tests) plus the authorities configured in NetCheck, which are returned too.
func (r *Runner) trustPool(pems []string) (*x509.CertPool, []*x509.Certificate, error) {
	if len(pems) == 0 {
		return r.RootCAs, nil, nil
	}
	extra, err := probes.ParseTrustedCAs(pems)
	if err != nil {
		return nil, nil, err
	}
	var pool *x509.CertPool
	if r.RootCAs != nil {
		pool = r.RootCAs.Clone()
	} else if pool, err = x509.SystemCertPool(); err != nil {
		pool = x509.NewCertPool()
	}
	for _, c := range extra {
		pool.AddCert(c)
	}
	return pool, extra, nil
}

// configuredAuthority returns the name of the configured authority every
// chain ends at, or "" when a chain ends at another (public) authority.
func configuredAuthority(chains [][]*x509.Certificate, extra []*x509.Certificate) string {
	name := ""
	for _, chain := range chains {
		root := chain[len(chain)-1]
		configured := false
		for _, c := range extra {
			if bytes.Equal(c.Raw, root.Raw) {
				configured = true
				break
			}
		}
		if !configured {
			return ""
		}
		if name == "" {
			name = probes.CertName(root)
		}
	}
	return name
}

// selfSigned reports a certificate issued and signed by itself (a server
// certificate made without a CA, which CheckSignatureFrom would refuse).
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
