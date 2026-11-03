package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

func mustProxies(t *testing.T, st *store.Store) *Proxies {
	t.Helper()
	h, err := LoadProxies(context.Background(), st, nil, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func proxyBody(name, host string, port int, shared bool, certs ...string) string {
	b, _ := json.Marshal(ProxyInput{Name: name, Host: host, Port: port, Shared: shared, Certificates: certs})
	return string(b)
}

func createdProxy(t *testing.T, f *fixture, session, path, body string) ProxyView {
	t.Helper()
	rec := f.do(session, "POST", path, body)
	var v ProxyView
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("create %s: %d %s", body, rec.Code, rec.Body)
	}
	return v
}

func catalogProxyNames(t *testing.T, f *fixture, session string) []string {
	t.Helper()
	var cat struct{ Proxies []ProxyView }
	json.Unmarshal(f.do(session, "GET", "/api/v1/probes/catalog", "").Body.Bytes(), &cat)
	names := []string{}
	for _, p := range cat.Proxies {
		names = append(names, p.Name)
	}
	return names
}

func TestAdminProxies(t *testing.T) {
	f := newFixture(t)
	ca := caPEM(t, "Proxy CA")
	corp := createdProxy(t, f, f.admin, "/api/v1/admin/proxies", proxyBody("corp", "10.0.0.9", 443, true, ca))
	if !corp.Shared || corp.Personal || len(corp.Certificates) != 1 || corp.CertificateCount != 1 {
		t.Errorf("shared proxy = %+v", corp)
	}
	adminsOnly := createdProxy(t, f, f.admin, "/api/v1/admin/proxies", proxyBody("ops", "10.0.0.10", 443, false))
	for body, code := range map[string]string{
		proxyBody("corp", "10.0.0.11", 443, true):     "duplicate_proxy_name",
		proxyBody("Corp", "10.0.0.11", 443, true):     "invalid_proxy_name",
		proxyBody("far", "192.0.2.10", 443, true):     "proxy_denied", // outside the destination policy
		proxyBody("bad", "10.0.0.11", 443, true, "x"): "invalid_certificate",
	} {
		if rec := f.do(f.admin, "POST", "/api/v1/admin/proxies", body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	// Only administrators change the administrators' proxies.
	if rec := f.do(f.user, "POST", "/api/v1/admin/proxies", proxyBody("mine", "10.0.0.12", 443, true)); rec.Code != http.StatusForbidden {
		t.Errorf("user POST: %d", rec.Code)
	}
	if rec := f.do(f.user, "DELETE", "/api/v1/proxies/"+corp.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("user deleting a shared proxy: %d", rec.Code)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/proxies/"+corp.ID, proxyBody("corp", "10.0.0.9", 80, true)); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"port":80,`) || !strings.Contains(rec.Body.String(), `"certificateCount":0`) {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}
	// Users see the shared proxies only; administrators also the ones kept for them.
	if got := catalogProxyNames(t, f, f.user); len(got) != 1 || got[0] != "corp" {
		t.Errorf("user catalog = %v", got)
	}
	if got := catalogProxyNames(t, f, f.admin); len(got) != 2 {
		t.Errorf("admin catalog = %v", got)
	}
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.0.0.1","checks":[{"method":"tcp","port":443,"proxy":"ops"}]}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "proxy_unknown") {
		t.Errorf("user with an administrators-only proxy: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/proxies/"+adminsOnly.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	evs, _ := f.store.ListAudit(context.Background(), "")
	audited := 0
	for _, ev := range evs {
		if strings.HasPrefix(ev.Action, "proxies.") && strings.Contains(ev.DetailsJSON, "10.0.0.") && !strings.Contains(ev.DetailsJSON, "BEGIN CERTIFICATE") {
			audited++
		}
	}
	if audited != 4 {
		t.Errorf("audited proxy changes = %d, want 4", audited)
	}

	// Managed in Helm: the administrators' proxies are read-only, personal ones are not.
	f.srv.Proxies.helm = []store.ProxyRecord{{ID: "helm-corp", Name: "corp", Host: "10.0.0.9", Port: 443, Shared: true, CAsJSON: "[]"}}
	if rec := f.do(f.admin, "POST", "/api/v1/admin/proxies", proxyBody("new", "10.0.0.13", 443, true)); rec.Code != http.StatusConflict {
		t.Errorf("helm-managed POST: %d", rec.Code)
	}
	if rec := f.do(f.user, "POST", "/api/v1/proxies", proxyBody("mine", "10.0.0.14", 443, false)); rec.Code != http.StatusCreated {
		t.Errorf("personal proxy with helm-managed shared ones: %d %s", rec.Code, rec.Body)
	}
}

func TestPersonalProxies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	shared := createdProxy(t, f, f.admin, "/api/v1/admin/proxies", proxyBody("corp", "10.0.0.9", 443, true))
	ca := caPEM(t, "Bob's inspection CA")
	// A personal proxy is never shared, whatever the body says.
	mine := createdProxy(t, f, f.user, "/api/v1/proxies", proxyBody("mine", "10.0.0.20", 443, true, ca))
	if !mine.Personal || mine.Shared || len(mine.Certificates) != 1 {
		t.Fatalf("personal proxy = %+v", mine)
	}
	// Nobody else sees or changes it, administrators included.
	var list struct{ Proxies []ProxyView }
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/proxies", "").Body.Bytes(), &list)
	if len(list.Proxies) != 1 || list.Proxies[0].ID != mine.ID {
		t.Errorf("owner's list = %+v", list.Proxies)
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/proxies", "").Body.Bytes(), &list)
	if len(list.Proxies) != 0 {
		t.Errorf("admin sees another user's personal proxies: %+v", list.Proxies)
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/proxies", "").Body.Bytes(), &list)
	if len(list.Proxies) != 1 || list.Proxies[0].ID != shared.ID {
		t.Errorf("admin list includes personal proxies: %+v", list.Proxies)
	}
	if names := catalogProxyNames(t, f, f.admin); strings.Contains(strings.Join(names, ","), "mine") {
		t.Errorf("admin catalog = %v", names)
	}
	for _, method := range []string{"PUT", "DELETE"} {
		if rec := f.do(f.admin, method, "/api/v1/proxies/"+mine.ID, proxyBody("x", "10.0.0.21", 443, false)); rec.Code != http.StatusNotFound {
			t.Errorf("admin %s of a personal proxy: %d", method, rec.Code)
		}
	}
	if rec := f.do(f.admin, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.0.0.1","checks":[{"method":"tcp","port":443,"proxy":"`+mine.ID+`"}]}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "proxy_unknown") {
		t.Errorf("admin using a personal proxy: %d %s", rec.Code, rec.Body)
	}

	// The owner uses it by name or ID; its authority travels only with it.
	runSpec := func(body string) probes.Spec {
		t.Helper()
		rec := f.do(f.user, "POST", "/api/v1/runs", body)
		var run struct{ ID string }
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &run) != nil {
			t.Fatalf("run %s: %d %s", body, rec.Code, rec.Body)
		}
		stored, _, _ := f.store.GetRun(ctx, run.ID)
		var s probes.Spec
		json.Unmarshal([]byte(stored.SpecJSON), &s)
		return s
	}
	s := runSpec(`{"namespace":"payments","target":"api.payments.svc.cluster.local","checks":[{"method":"https","proxy":"mine"},{"method":"http","proxy":"corp"}]}`)
	if p := s.Checks[0].Proxy; p == nil || p.ID != mine.ID || !p.Personal || len(p.TrustedCAs) != 1 || s.Checks[1].Proxy == nil || s.Checks[1].Proxy.Personal {
		t.Errorf("spec proxies = %+v / %+v", s.Checks[0].Proxy, s.Checks[1].Proxy)
	}

	// A name of both a personal and a shared proxy must be chosen by ID.
	createdProxy(t, f, f.user, "/api/v1/proxies", proxyBody("corp", "10.0.0.22", 443, false))
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.0.0.1","checks":[{"method":"tcp","port":443,"proxy":"corp"}]}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "proxy_ambiguous") {
		t.Errorf("ambiguous name: %d %s", rec.Code, rec.Body)
	}
	if s := runSpec(`{"namespace":"payments","target":"10.0.0.1","checks":[{"method":"tcp","port":443,"proxy":"` + shared.ID + `"}]}`); s.Checks[0].Proxy == nil || s.Checks[0].Proxy.ID != shared.ID {
		t.Errorf("shared proxy by ID = %+v", s.Checks[0].Proxy)
	}

	// At most MaxPersonalProxies each.
	for i := 3; i <= probes.MaxPersonalProxies; i++ {
		createdProxy(t, f, f.user, "/api/v1/proxies", proxyBody("p"+string(rune('a'+i)), "10.0.0.30", 443, false))
	}
	if rec := f.do(f.user, "POST", "/api/v1/proxies", proxyBody("one-too-many", "10.0.0.31", 443, false)); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "too_many_proxies") {
		t.Errorf("limit: %d %s", rec.Code, rec.Body)
	}
}

func TestPersonalProxyHiddenFromOthers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	bob, _ := f.store.GetUserByUsername(ctx, "bob")
	const id = "eeeeeeeeeeeeeeee"
	err := f.store.CreateRun(ctx, store.Run{ID: id, CreatedAt: time.Now(), ActorID: bob.ID, Namespace: "payments", ClusterID: "lab",
		Target: "api.example.com", Status: "queued", SpecJSON: "{}",
		RequestJSON: `{"namespace":"payments","target":"api.example.com","checks":[{"method":"tcp","port":443,"proxy":"p123"}]}`},
		[]store.Execution{{ID: id + "-1", Seq: 1, CheckID: "1-tcp", Method: "tcp", Status: "queued"}}, store.AuditEvent{Action: "seed", Outcome: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	cr := probes.CheckResult{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusFailed, Category: "proxy_denied",
		Error:      `proxy home (proxy.bob.example:3128) answered "403 Forbidden" to CONNECT api.example.com:443`,
		Equivalent: []string{"nc", "-z", "-v", "-w", "5", "-X", "connect", "-x", "proxy.bob.example:3128", "api.example.com", "443"},
		Proxy: &probes.ProxyResult{Name: "home", Address: "proxy.bob.example:3128", Personal: true, Mode: probes.ProxyModeConnect,
			ResolvedIPs: []string{"10.0.0.40"}, UsedIP: "10.0.0.40", Reached: true, Status: 403, StatusText: "403 Forbidden"}}
	result, _ := json.Marshal(cr)
	diag := `{"category":"proxy_denied","severity":"error","summary":"x","detail":"Tested through the proxy home: the direct path from the Pod was not tested.","conclusive":true,"proxy":"home"}`
	argv := `["nc","-z","-v","-w","5","-X","connect","-x","proxy.bob.example:3128","api.example.com","443"]`
	err = f.store.CompleteRun(ctx, id, store.Completion{Status: store.RunFailed, FinishedAt: time.Now(), Executions: []store.Execution{{
		CheckID: "1-tcp", Status: "failed", Category: "proxy_denied", ArgvJSON: argv, ResolvedIPsJSON: "[]", DiagnosisJSON: diag, ResultJSON: string(result),
		Stdout: "resolved proxy.bob.example (ip) -> 10.0.0.40\nconnecting to proxy home at 10.0.0.40:3128\nconnected to proxy home\nCONNECT api.example.com:443", Stderr: cr.Error}}})
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"proxy.bob.example", "10.0.0.40", `"home"`, "proxy home", "p123"}
	for who, session := range map[string]string{"author": f.user, "admin": f.admin} {
		rec := f.do(session, "GET", "/api/v1/runs/"+id, "")
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", who, rec.Code)
		}
		for _, s := range secrets {
			if leaked := strings.Contains(body, s); leaked != (who == "author") {
				t.Errorf("%s: %q present=%v", who, s, leaked)
			}
		}
		if who == "admin" && (!strings.Contains(body, `"personal":true`) || !strings.Contains(body, "403 Forbidden") || !strings.Contains(body, personalProxyLabel)) {
			t.Errorf("admin view lost the result: %s", body)
		}
	}
}
