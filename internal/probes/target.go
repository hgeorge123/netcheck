package probes

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	maxRawTargetLen = 255
	maxHostnameLen  = 253
	maxLabelLen     = 63
	maxPathLen      = 1024
)

// FieldError is a single input validation failure, safe to return to clients.
// Code is stable and translated by the UI; Message is an English fallback.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Message }

// ValidationErrors aggregates FieldErrors.
type ValidationErrors []FieldError

func (v ValidationErrors) Error() string {
	parts := make([]string, len(v))
	for i, e := range v {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

func fieldErr(field, code, format string, args ...any) FieldError {
	return FieldError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)}
}

// ParseTarget validates a user supplied destination: an IPv4/IPv6 literal
// (IPv6 optionally in brackets) or a hostname. URLs are not accepted: every
// check carries its own port. It never resolves names; resolution happens
// inside the probe Pod.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fieldErr("target", "required", "the destination is required")
	}
	if len(raw) > maxRawTargetLen {
		return Target{}, fieldErr("target", "too_long", "the destination is longer than %d characters", maxRawTargetLen)
	}
	for _, r := range raw {
		if r <= 0x20 || r >= 0x7f {
			return Target{}, fieldErr("target", "invalid_chars", "the destination contains spaces, control or non-ASCII characters (use punycode)")
		}
	}
	if strings.HasPrefix(raw, "-") {
		return Target{}, fieldErr("target", "flag_like", "the destination cannot start with '-'")
	}
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#@") {
		return Target{}, fieldErr("target", "url_not_supported", "enter a hostname or IP address only; set ports and paths in each check")
	}
	host, isIP, err := parseHost(raw)
	if err != nil {
		return Target{}, err
	}
	return Target{Raw: raw, Host: host, IsIP: isIP}, nil
}

// parseHost returns the canonical host and whether it is an IP literal.
func parseHost(s string) (string, bool, error) {
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return "", false, fieldErr("target", "invalid_ipv6", "malformed bracketed IPv6 address")
		}
		addr, err := netip.ParseAddr(s[1 : len(s)-1])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", false, fieldErr("target", "invalid_ipv6", "invalid bracketed IPv6 address (zones are not allowed)")
		}
		return addr.Unmap().String(), true, nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Zone() != "" {
			return "", false, fieldErr("target", "ipv6_zone", "IPv6 zones are not allowed")
		}
		return addr.Unmap().String(), true, nil
	}
	if strings.Contains(s, "%") {
		return "", false, fieldErr("target", "ipv6_zone", "IPv6 zones are not allowed")
	}
	if strings.Contains(s, ":") {
		return "", false, fieldErr("target", "host_port", "invalid format: set the port in each check")
	}
	host, err := normalizeHostname(s)
	if err != nil {
		return "", false, err
	}
	return host, false, nil
}

func normalizeHostname(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(s), ".")
	if h == "" || len(h) > maxHostnameLen {
		return "", fieldErr("target", "invalid_hostname", "empty or too long hostname")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen {
			return "", fieldErr("target", "invalid_hostname", "empty DNS label or longer than %d characters", maxLabelLen)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", fieldErr("target", "invalid_hostname", "a DNS label cannot start or end with '-'")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fieldErr("target", "invalid_hostname", "character not allowed in hostname: %q", c)
			}
		}
	}
	// A purely numeric last label is never a valid hostname and is how
	// shorthand/decimal IP notations (e.g. 127.1, 2130706433) look.
	if isAllDigits(labels[len(labels)-1]) {
		return "", fieldErr("target", "ambiguous_numeric_host", "shorthand or numeric IP notation is not allowed; use the canonical form")
	}
	return h, nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// ValidatePort checks a TCP port number.
func ValidatePort(p int) error {
	if p < 1 || p > 65535 {
		return fieldErr("port", "invalid_port", "the port must be between 1 and 65535")
	}
	return nil
}

// ValidatePath checks an already escaped absolute HTTP path.
func ValidatePath(p string) error {
	if !strings.HasPrefix(p, "/") || len(p) > maxPathLen {
		return fieldErr("http.path", "invalid_path", "the path must start with '/' and be at most %d characters", maxPathLen)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		case c == '%':
			if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
				return fieldErr("http.path", "invalid_path", "invalid %% escape sequence")
			}
		default:
			return fieldErr("http.path", "invalid_path", "character not allowed in the path: %q", c)
		}
	}
	return nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
