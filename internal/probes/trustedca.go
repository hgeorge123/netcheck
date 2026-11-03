package probes

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// Limits of the trusted certificate authorities. They travel inside the
// spec of every HTTPS run (an environment variable of the probe Pod).
const (
	MaxTrustedCAs     = 50
	MaxTrustedCABytes = 64 << 10
)

// NormalizeTrustedCAs parses certificate authorities the probe trusts on top
// of the public ones (a corporate PKI, a TLS inspection proxy). Each entry
// may hold several PEM certificates (a bundle). It returns one PEM per
// certificate without duplicates. Anything that is not a CA certificate is
// refused, a private key pasted by mistake included.
func NormalizeTrustedCAs(entries []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	total := 0
	for i, entry := range entries {
		field := fmt.Sprintf("certificates[%d]", i)
		rest := []byte(strings.TrimSpace(entry))
		if len(rest) == 0 {
			continue
		}
		found := false
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, fieldErr(field, "not_a_certificate", "only CERTIFICATE blocks are accepted, found %q: never paste private keys", block.Type)
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fieldErr(field, "invalid_certificate", "the certificate cannot be read: %v", err)
			}
			if !c.IsCA {
				return nil, fieldErr(field, "not_a_ca", "%s is not a certificate authority (basic constraints CA:FALSE)", CertName(c))
			}
			found = true
			fp := Fingerprint(c)
			if seen[fp] {
				continue
			}
			seen[fp] = true
			p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
			total += len(p)
			out = append(out, p)
		}
		if len(bytes.TrimSpace(rest)) > 0 || !found {
			return nil, fieldErr(field, "invalid_certificate", "the text is not a PEM certificate (-----BEGIN CERTIFICATE-----)")
		}
	}
	if len(out) > MaxTrustedCAs {
		return nil, fieldErr("certificates", "too_many_certificates", "at most %d certificates", MaxTrustedCAs)
	}
	if total > MaxTrustedCABytes {
		return nil, fieldErr("certificates", "certificates_too_large", "the certificates take more than %d KiB", MaxTrustedCABytes>>10)
	}
	return out, nil
}

// ParseTrustedCAs parses certificates already normalized (one PEM each).
func ParseTrustedCAs(pems []string) ([]*x509.Certificate, error) {
	norm, err := NormalizeTrustedCAs(pems)
	if err != nil {
		return nil, err
	}
	if len(norm) != len(pems) {
		return nil, fieldErr("certificates", "invalid_certificate", "every entry must hold exactly one certificate")
	}
	out := make([]*x509.Certificate, len(norm))
	for i, p := range norm {
		block, _ := pem.Decode([]byte(p))
		out[i], _ = x509.ParseCertificate(block.Bytes)
	}
	return out, nil
}

// Fingerprint is the SHA-256 of the certificate in lowercase hex.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// CertName is the subject common name, or the full subject without one.
func CertName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
