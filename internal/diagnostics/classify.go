// Package diagnostics classifies probe errors into stable categories and
// produces non-conclusive, human readable interpretations.
package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

// Categories are stable identifiers stored in the database and used by the UI.
const (
	CategoryOK                = "ok"
	CategoryDestinationDenied = "destination_denied"
	CategoryDNSNXDomain       = "dns_nxdomain"
	CategoryDNSServFail       = "dns_servfail"
	CategoryDNSTimeout        = "dns_timeout"
	CategoryDNSError          = "dns_error"
	CategoryDNSNoAddress      = "dns_no_address"
	CategoryTCPRefused        = "tcp_refused"
	CategoryTimeout           = "timeout"
	CategoryNoRoute           = "no_route"
	CategoryNetUnreachable    = "network_unreachable"
	CategoryConnReset         = "connection_reset"
	CategoryTLSCert           = "tls_cert_failure"
	CategoryTLSHandshake      = "tls_handshake_failure"
	CategoryHTTPResponse      = "http_response"
	CategoryHTTPProtocol      = "http_protocol_error"
	CategoryUDPPortClosed     = "udp_port_closed"
	CategoryUDPNoReply        = "udp_no_reply"
	CategoryUDPUnexpected     = "udp_unexpected_reply"
	CategoryICMPPartialLoss   = "icmp_partial_loss"
	CategoryICMPNoReply       = "icmp_no_reply"
	CategoryICMPUnreachable   = "icmp_unreachable"
	CategoryICMPNotPermitted  = "icmp_not_permitted"
	// CategoryTracerouteIncomplete means the destination was not reached.
	CategoryTracerouteIncomplete = "traceroute_incomplete"
	CategoryError                = "error"
	CategoryInfraError           = "infra_error"
	CategoryAdmissionRejected    = "admission_rejected"
	CategoryProbeOutputInvalid   = "probe_output_invalid"
)

// DeniedChecker lets callers recognise policy denials without importing the
// probes package here.
type DeniedChecker func(error) bool

// Classify maps a Go network error to a category. isDenied recognises policy
// denials, which must never be reported as network failures.
func Classify(err error, isDenied DeniedChecker) string {
	if err == nil {
		return CategoryOK
	}
	if isDenied != nil && isDenied(err) {
		return CategoryDestinationDenied
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return CategoryDNSNXDomain
		case dnsErr.IsTimeout:
			return CategoryDNSTimeout
		case strings.Contains(dnsErr.Err, "server misbehaving"):
			// The Go resolver reports SERVFAIL/REFUSED rcodes this way.
			return CategoryDNSServFail
		default:
			return CategoryDNSError
		}
	}

	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) {
		return CategoryTLSCert
	}
	var recErr tls.RecordHeaderError
	var alertErr tls.AlertError
	if errors.As(err, &recErr) || errors.As(err, &alertErr) || strings.Contains(err.Error(), "tls: ") {
		return CategoryTLSHandshake
	}

	switch {
	case isErrno(err, syscall.ECONNREFUSED, wsaConnRefused):
		return CategoryTCPRefused
	case isErrno(err, syscall.EHOSTUNREACH, wsaHostUnreach):
		return CategoryNoRoute
	case isErrno(err, syscall.ENETUNREACH, wsaNetUnreach):
		return CategoryNetUnreachable
	case isErrno(err, syscall.ECONNRESET, wsaConnReset):
		return CategoryConnReset
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return CategoryTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTimeout
	}
	return CategoryError
}

// Windows socket error numbers, so the classifier behaves the same when
// unit tests run on a Windows workstation. The probe itself runs on Linux.
const (
	wsaConnReset   = syscall.Errno(10054)
	wsaConnRefused = syscall.Errno(10061)
	wsaNetUnreach  = syscall.Errno(10051)
	wsaHostUnreach = syscall.Errno(10065)
)

func isErrno(err error, targets ...syscall.Errno) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	for _, t := range targets {
		if errno == t {
			return true
		}
	}
	return false
}
