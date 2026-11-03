package diagnostics

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

type deniedErr struct{}

func (deniedErr) Error() string { return "denied" }

func isDenied(err error) bool { var d deniedErr; return errors.As(err, &d) }

func TestClassify(t *testing.T) {
	op := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: err}}
	}
	cases := []struct {
		err  error
		want string
	}{
		{nil, CategoryOK},
		{fmt.Errorf("wrap: %w", deniedErr{}), CategoryDestinationDenied},
		{&net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}, CategoryDNSNXDomain},
		{&net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true}, CategoryDNSTimeout},
		{&net.DNSError{Err: "server misbehaving", Name: "x"}, CategoryDNSServFail},
		{&net.DNSError{Err: "weird", Name: "x"}, CategoryDNSError},
		{op(syscall.ECONNREFUSED), CategoryTCPRefused},
		{op(syscall.Errno(10061)), CategoryTCPRefused},
		{op(syscall.EHOSTUNREACH), CategoryNoRoute},
		{op(syscall.ENETUNREACH), CategoryNetUnreachable},
		{op(syscall.ECONNRESET), CategoryConnReset},
		{context.DeadlineExceeded, CategoryTimeout},
		{fmt.Errorf("dial: %w", os.ErrDeadlineExceeded), CategoryTimeout},
		{x509.UnknownAuthorityError{}, CategoryTLSCert},
		{x509.HostnameError{Host: "x"}, CategoryTLSCert},
		{errors.New("tls: handshake failure"), CategoryTLSHandshake},
		{errors.New("boom"), CategoryError},
	}
	for _, c := range cases {
		if got := Classify(c.err, isDenied); got != c.want {
			t.Errorf("Classify(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestDiagnoseHTTPIsNotRedForAppErrors(t *testing.T) {
	for _, code := range []int{401, 403, 404, 500, 503} {
		d := Diagnose("http", CategoryHTTPResponse, code)
		if d.Severity == SeverityError {
			t.Errorf("HTTP %d must not be reported as a network error", code)
		}
	}
	if Diagnose("http", CategoryHTTPResponse, 200).Severity != SeveritySuccess {
		t.Error("HTTP 200 should be success")
	}
}

func TestDiagnoseTimeoutIsNotConclusive(t *testing.T) {
	d := Diagnose("tcp", CategoryTimeout, 0)
	if d.Conclusive {
		t.Error("timeout must never be conclusive")
	}
	if d.Detail == "" {
		t.Error("timeout needs an explanation")
	}
}

func TestDiagnoseKnownCategoriesHaveSummary(t *testing.T) {
	for _, c := range []string{CategoryOK, CategoryICMPNoReply, CategoryICMPUnreachable, CategoryICMPNotPermitted, CategoryTracerouteIncomplete, CategoryDestinationDenied, CategoryDNSNXDomain, CategoryDNSServFail, CategoryDNSTimeout,
		CategoryDNSNoAddress, CategoryDNSError, CategoryTCPRefused, CategoryTimeout, CategoryNoRoute, CategoryNetUnreachable,
		CategoryConnReset, CategoryTLSCert, CategoryTLSHandshake, CategoryHTTPProtocol, CategoryAdmissionRejected,
		CategoryInfraError, CategoryProbeOutputInvalid} {
		if Diagnose("tcp", c, 0).Summary == "" {
			t.Errorf("category %s has no summary", c)
		}
	}
}

func TestDiagnoseICMP(t *testing.T) {
	if d := Diagnose("ping", CategoryOK, 0); d.Severity != SeveritySuccess {
		t.Errorf("ping ok = %+v", d)
	}
	if d := Diagnose("ping", CategoryICMPNoReply, 0); d.Conclusive || d.Detail == "" {
		t.Errorf("no ICMP reply must explain that ICMP may be filtered: %+v", d)
	}
	if d := Diagnose("ping", CategoryICMPPartialLoss, 0); d.Severity != SeverityWarning {
		t.Errorf("partial loss = %+v", d)
	}
	if d := Diagnose("traceroute", CategoryTracerouteIncomplete, 0); d.Severity == SeverityError || d.Conclusive {
		t.Errorf("incomplete traceroute must not look like a hard failure: %+v", d)
	}
	if d := Diagnose("http", CategoryHTTPResponse, 404); d.HTTPStatus != 404 {
		t.Errorf("http status not carried: %+v", d)
	}
}

func TestIgnoredCertificateIsNeverACleanSuccess(t *testing.T) {
	d := WithIgnoredCertificate(Diagnose("https", CategoryHTTPResponse, 200), "the certificate expired on 2026-01-01T00:00:00Z")
	if d.Severity != SeverityWarning || !d.TLSIgnored || !strings.Contains(d.Detail, "Certificate errors were ignored as requested: the certificate expired") {
		t.Fatalf("diagnosis = %+v", d)
	}
	if d := WithIgnoredCertificate(Diagnose("https", CategoryHTTPResponse, 503), "x"); d.Severity != SeverityWarning {
		t.Errorf("a 503 keeps its warning: %+v", d)
	}
}

func TestWithProxy(t *testing.T) {
	d := WithProxy(Diagnose("tcp", CategoryOK, 0), "tcp", "corp")
	if d.Proxy != "corp" || d.Summary != "TCP tunnel established through the proxy." || !strings.Contains(d.Detail, "direct path from the Pod was not tested") {
		t.Errorf("tcp through proxy = %+v", d)
	}
	d = WithProxy(Diagnose("https", CategoryProxyDenied, 0), "https", "corp")
	if !d.Conclusive || d.Severity != SeverityError || !strings.HasPrefix(d.Summary, "The proxy refused") {
		t.Errorf("proxy denied = %+v", d)
	}
	if d := Diagnose("tcp", CategoryProxyUnreachable, 0); d.Conclusive || !strings.Contains(d.Detail, "between the Pod and the proxy") {
		t.Errorf("proxy unreachable = %+v", d)
	}
}
