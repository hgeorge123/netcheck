package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hgeorge123/netcheck/internal/probes"
)

func TestParseCheck(t *testing.T) {
	ok := map[string]probes.CheckRequest{
		"dns":           {Method: probes.MethodDNS},
		"tcp:5432":      {Method: probes.MethodTCP, Port: 5432},
		"udp:514":       {Method: probes.MethodUDP, Port: 514, UDP: &probes.UDPOptions{Protocol: probes.UDPGeneric}},
		"udp-dns":       {Method: probes.MethodUDP, Port: 53, UDP: &probes.UDPOptions{Protocol: probes.UDPDNS}},
		"udp-ntp:1123":  {Method: probes.MethodUDP, Port: 1123, UDP: &probes.UDPOptions{Protocol: probes.UDPNTP}},
		"http":          {Method: probes.MethodHTTP, Port: 80},
		"https":         {Method: probes.MethodHTTPS, Port: 443},
		"https/health":  {Method: probes.MethodHTTPS, Port: 443, HTTP: &probes.HTTPOptions{Method: "GET", Path: "/health"}},
		"http:8080/a/b": {Method: probes.MethodHTTP, Port: 8080, HTTP: &probes.HTTPOptions{Method: "GET", Path: "/a/b"}},
		"ping:3":        {Method: probes.MethodPing, Ping: &probes.PingOptions{Count: 3}},
		"traceroute:12": {Method: probes.MethodTraceroute, Traceroute: &probes.TracerouteOptions{MaxHops: 12}},
		"  tcp:443  ":   {Method: probes.MethodTCP, Port: 443},
	}
	for in, want := range ok {
		got, err := parseCheck(in)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if err != nil || string(g) != string(w) {
			t.Errorf("%q = %s, %v; want %s", in, g, err, w)
		}
	}
	for _, bad := range []string{"tcp", "tcp:0", "tcp:70000", "udp", "dns:53", "ftp:21", "ping:99", "https:abc"} {
		if _, err := parseCheck(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// fakeAPI answers like NetCheck: the run is queued, running, then final.
func fakeAPI(t *testing.T, final string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	polls := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nck_test" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"invalid or expired session"}}`))
			return
		}
		var req runRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Namespace != "payments" || len(req.Checks) != 2 {
			t.Errorf("request = %+v %v", req, err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"abcdef0123456789","status":"queued"}`))
	})
	mux.HandleFunc("GET /api/v1/runs/{id}", func(w http.ResponseWriter, _ *http.Request) {
		status := final
		if polls.Add(1) == 1 {
			status = "running"
		}
		_, _ = w.Write([]byte(`{"id":"abcdef0123456789","status":"` + status + `","namespace":"payments","target":"db",
			"checks":[{"method":"tcp","status":"timed_out","usedIp":"10.0.0.5","durationMs":5000,"result":{"port":5432},
			"diagnosis":{"summary":"Timed out without an answer."}}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, polls
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRunExitCodes(t *testing.T) {
	args := []string{"run", "-n", "payments", "-t", "db", "-c", "dns", "-c", "tcp:5432"}
	for final, code := range map[string]int{"succeeded": 0, "failed": 1, "infra_error": 2} {
		srv, polls := fakeAPI(t, final)
		var out bytes.Buffer
		err := run(context.Background(), args, env(map[string]string{"NETCHECK_URL": strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), "NETCHECK_TOKEN": "nck_test"}), &out)
		var ee exitError
		got := 0
		if errors.As(err, &ee) {
			got = ee.code
		}
		if got != code || polls.Load() < 2 {
			t.Errorf("%s: exit %d (%v), polls %d", final, got, err, polls.Load())
		}
		if !strings.Contains(out.String(), "TCP 5432  timed_out  10.0.0.5  5000 ms  Timed out without an answer.") ||
			!strings.Contains(out.String(), "/#/runs/abcdef0123456789") {
			t.Errorf("%s output:\n%s", final, out.String())
		}
	}
}

func TestRunConfigurationErrors(t *testing.T) {
	srv, _ := fakeAPI(t, "succeeded")
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	args := []string{"run", "-n", "payments", "-t", "db", "-c", "dns", "-c", "tcp:5432"}
	cases := map[string]map[string]string{
		"no URL":         {"NETCHECK_TOKEN": "nck_test"},
		"plain http":     {"NETCHECK_URL": "http://netcheck.example.com", "NETCHECK_TOKEN": "nck_test"},
		"not a token":    {"NETCHECK_URL": base, "NETCHECK_TOKEN": "password"},
		"rejected token": {"NETCHECK_URL": base, "NETCHECK_TOKEN": "nck_wrong"},
		"missing CA":     {"NETCHECK_URL": base, "NETCHECK_TOKEN": "nck_test", "NETCHECK_CA_FILE": "does-not-exist.pem"},
	}
	for name, e := range cases {
		err := run(context.Background(), args, env(e), &bytes.Buffer{})
		var ee exitError
		if !errors.As(err, &ee) || ee.code != 3 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := run(context.Background(), []string{"run", "-n", "payments", "-t", "db", "-c", "ftp:21"}, env(nil), &bytes.Buffer{}); err == nil {
		t.Error("an unknown check was accepted")
	}
}
