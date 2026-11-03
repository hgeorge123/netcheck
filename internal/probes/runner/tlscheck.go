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
}

// inspectCertificate checks the server certificate the way a browser would,
// but reports every problem instead of stopping at the first: validity
// dates, the host name and the chain of trust are checked independently.
func inspectCertificate(certs []*x509.Certificate, host string, roots *x509.CertPool, now time.Time) certReport {
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
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at}); err != nil {
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

// selfSigned reports a certificate issued and signed by itself (a server
// certificate made without a CA, which CheckSignatureFrom would refuse).
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
