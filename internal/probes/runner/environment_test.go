package runner

import "testing"

func TestSanitize(t *testing.T) {
	in := "\x1b[31mred\x1b[0m\x00 ok\ttab\nline\x07\x1b]0;title\x07end\u009b"
	want := "red ok\ttab\nlineend"
	if got := Sanitize(in); got != want {
		t.Errorf("Sanitize = %q, want %q", got, want)
	}
	if got := Sanitize("bad\xffutf8"); got != "bad�utf8" {
		t.Errorf("Sanitize invalid utf8 = %q", got)
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s, cut := Truncate("añb", 2) // "a" + first byte of "ñ"
	if s != "a" || !cut {
		t.Errorf("Truncate = %q %v", s, cut)
	}
	if s, cut := Truncate("abc", 5); s != "abc" || cut {
		t.Errorf("Truncate short = %q %v", s, cut)
	}
}

func TestParseResolvConf(t *testing.T) {
	info := ParseResolvConf("# comment\nnameserver 10.96.0.10\nsearch payments.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5 timeout:1\n")
	if len(info.Nameservers) != 1 || info.Nameservers[0] != "10.96.0.10" || len(info.Search) != 3 || info.Ndots != 5 {
		t.Errorf("info = %+v", info)
	}
}

func TestDetectSourceFlagsCredentials(t *testing.T) {
	env := map[string]string{"POD_NAMESPACE": "payments", "POD_IP": "10.1.1.1", "NODE_NAME": "n1", "POD_NAME": "p"}
	none := func(string) bool { return false }
	src := DetectSource(func(k string) string { return env[k] }, none)
	if src.SATokenMounted || src.CloudCredentialsHint || src.Namespace != "payments" || src.PodIP != "10.1.1.1" {
		t.Errorf("src = %+v", src)
	}
	env["AWS_ROLE_ARN"] = "arn:aws:iam::123:role/x"
	all := func(string) bool { return true }
	src = DetectSource(func(k string) string { return env[k] }, all)
	if !src.SATokenMounted || !src.CloudCredentialsHint {
		t.Errorf("credentials not flagged: %+v", src)
	}
}
