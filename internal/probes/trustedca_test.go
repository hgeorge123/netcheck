package probes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, name string, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestNormalizeTrustedCAs(t *testing.T) {
	a, b := testCert(t, "Corp Root", true), testCert(t, "Proxy CA", true)

	// A bundle is split, duplicates are dropped, blank entries are ignored.
	got, err := NormalizeTrustedCAs([]string{"  " + a + b + "\n", a, ""})
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("normalize = %d %v", len(got), err)
	}
	certs, err := ParseTrustedCAs(got)
	if err != nil || CertName(certs[1]) != "Proxy CA" || len(Fingerprint(certs[0])) != 64 {
		t.Fatalf("parse = %v", err)
	}
	if empty, err := NormalizeTrustedCAs(nil); err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("no certificates = %v %v", empty, err)
	}

	key := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n"
	for name, tc := range map[string]struct {
		in   []string
		code string
	}{
		"private key":       {[]string{a, key}, "not_a_certificate"},
		"server cert":       {[]string{testCert(t, "api.example.com", false)}, "not_a_ca"},
		"not PEM":           {[]string{"hello"}, "invalid_certificate"},
		"text after a cert": {[]string{a + "garbage"}, "invalid_certificate"},
		"broken DER":        {[]string{"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}, "invalid_certificate"},
		"too many":          {manyCAs(t, MaxTrustedCAs+1), "too_many_certificates"},
	} {
		_, err := NormalizeTrustedCAs(tc.in)
		var fe FieldError
		if !errors.As(err, &fe) || fe.Code != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The probe accepts only normalized lists: one certificate per entry.
	if _, err := ParseTrustedCAs([]string{a + b}); err == nil {
		t.Error("a bundle in the spec must be refused")
	}
}

func manyCAs(t *testing.T, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = testCert(t, "CA "+strings.Repeat("x", i%3), true)
	}
	return out
}

func TestSpecValidateTrustedCAs(t *testing.T) {
	s := validSpecForTest(t)
	s.TrustedCAs = []string{testCert(t, "Corp Root", true)}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid authorities: %v", err)
	}
	s.TrustedCAs = []string{testCert(t, "api.example.com", false)}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "trustedCas") {
		t.Errorf("server certificate in the spec: %v", err)
	}
}

func validSpecForTest(t *testing.T) Spec {
	t.Helper()
	s, err := BuildSpec("abcdef0123456789", RunRequest{Target: "api.payments.svc.cluster.local", Checks: []CheckRequest{{Method: MethodHTTPS}}}, testPolicy(), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
