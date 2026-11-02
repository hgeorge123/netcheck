package probes

import "testing"

func TestParseTargetValid(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		isIP bool
	}{
		{raw: "10.20.30.40", host: "10.20.30.40", isIP: true},
		{raw: "  10.20.30.40 ", host: "10.20.30.40", isIP: true},
		{raw: "2001:db8::1", host: "2001:db8::1", isIP: true},
		{raw: "[2001:db8::1]", host: "2001:db8::1", isIP: true},
		{raw: "::ffff:10.0.0.1", host: "10.0.0.1", isIP: true},
		{raw: "API.Example.com.", host: "api.example.com"},
		{raw: "my-svc", host: "my-svc"},
		{raw: "my-svc.payments.svc.cluster.local", host: "my-svc.payments.svc.cluster.local"},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q) unexpected error: %v", c.raw, err)
		}
		if got.Host != c.host || got.IsIP != c.isIP {
			t.Errorf("ParseTarget(%q) = %+v", c.raw, got)
		}
	}
}

func TestParseTargetRejects(t *testing.T) {
	cases := map[string]string{
		"":                              "required",
		"-oProxyCommand=id":             "flag_like",
		"--help":                        "flag_like",
		"host name":                     "invalid_chars",
		"host;id":                       "invalid_hostname",
		"$(id)":                         "invalid_hostname",
		"`id`":                          "invalid_hostname",
		"a\nb":                          "invalid_chars",
		"münchen.de":                    "invalid_chars",
		"10.0.0.1:443":                  "host_port",
		"[2001:db8::1":                  "invalid_ipv6",
		"[10.0.0.1]":                    "invalid_ipv6",
		"fe80::1%eth0":                  "ipv6_zone",
		"[fe80::1%25eth0]":              "invalid_ipv6",
		"010.0.0.1":                     "ambiguous_numeric_host",
		"127.1":                         "ambiguous_numeric_host",
		"2130706433":                    "ambiguous_numeric_host",
		"-host.example.com":             "flag_like",
		"host-.example.com":             "invalid_hostname",
		"under_score.example.com":       "invalid_hostname",
		"https://api.example.com/":      "url_not_supported",
		"ftp://example.com":             "url_not_supported",
		"http://user:pass@example.com/": "url_not_supported",
		"example.com/path":              "url_not_supported",
		"user@example.com":              "url_not_supported",
		"a..b":                          "invalid_hostname",
	}
	for raw, code := range cases {
		_, err := ParseTarget(raw)
		fe, ok := err.(FieldError)
		if !ok {
			t.Errorf("ParseTarget(%q) error = %v, want FieldError code %s", raw, err, code)
			continue
		}
		if fe.Code != code {
			t.Errorf("ParseTarget(%q) code = %s, want %s", raw, fe.Code, code)
		}
	}
}

func TestValidatePort(t *testing.T) {
	for _, p := range []int{1, 80, 443, 65535} {
		if ValidatePort(p) != nil {
			t.Errorf("port %d should be valid", p)
		}
	}
	for _, p := range []int{-1, 0, 65536} {
		if ValidatePort(p) == nil {
			t.Errorf("port %d should be invalid", p)
		}
	}
}

func TestValidatePath(t *testing.T) {
	for _, p := range []string{"/", "/health", "/a/b-c_d.e~f", "/%2F"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("path %q should be valid: %v", p, err)
		}
	}
	for _, p := range []string{"", "health", "/a b", "/%zz", "/%2", "/a?b", "/a#b", "/\x00"} {
		if ValidatePath(p) == nil {
			t.Errorf("path %q should be invalid", p)
		}
	}
}
