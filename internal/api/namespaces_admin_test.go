package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

func withNamespaceAdmin(f *fixture) {
	web := auth.NewWebExclusions(f.ns, nil)
	f.srv.Authz.Source = web
	f.srv.Authz.OwnNamespace = "netcheck"
	f.srv.NSAdmin = &NamespaceAdmin{
		All: func(context.Context) ([]string, error) {
			return []string{"kube-system", "netcheck", "payments", "platform", "readonly", "secret"}, nil
		},
		Web:          web,
		HelmExcluded: []string{"platform"},
		System:       []string{"kube-system", "kube-public", "kube-node-lease", "default"},
	}
}

func TestAdminExcludesNamespacesFromTheWeb(t *testing.T) {
	f := newFixture(t)
	withNamespaceAdmin(f)

	if rec := f.do(f.user, "POST", "/api/v1/admin/namespace-exclusions", `{"name":"payments"}`); rec.Code != http.StatusForbidden {
		t.Errorf("user excluded a namespace: %d", rec.Code)
	}
	rec := f.do(f.admin, "GET", "/api/v1/admin/namespace-exclusions", "")
	body := rec.Body.String()
	for _, want := range []string{`"name":"kube-system","status":"system"`, `"name":"netcheck","status":"netcheck"`, `"name":"platform","status":"excluded_helm"`, `"name":"payments","status":"available"`} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %s: %s", want, body)
		}
	}

	// Exclude payments: hidden and blocked immediately, audited.
	if rec := f.do(f.admin, "POST", "/api/v1/admin/namespace-exclusions", `{"name":"payments","reason":"PCI scope"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("exclude: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "GET", "/api/v1/namespaces", ""); strings.Contains(rec.Body.String(), `"payments"`) {
		t.Errorf("excluded namespace still offered: %s", rec.Body)
	}
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.0.0.1","checks":[{"method":"tcp","port":443}]}`); rec.Code != http.StatusForbidden {
		t.Errorf("run in excluded namespace: %d %s", rec.Code, rec.Body)
	}
	if body := f.do(f.admin, "GET", "/api/v1/admin/namespace-exclusions", "").Body.String(); !strings.Contains(body, `"name":"payments","status":"excluded_web","exists":true,"reason":"PCI scope","excludedBy":"admin"`) {
		t.Errorf("web exclusion not listed: %s", body)
	}
	events, _ := f.store.ListAudit(context.Background(), "")
	if !hasAction(events, "namespace.exclude") {
		t.Error("namespace.exclude not audited")
	}

	// Already excluded, Helm, system and own namespace cannot be excluded again or removed from the web.
	for body, code := range map[string]int{`{"name":"payments"}`: 409, `{"name":"platform"}`: 409, `{"name":"kube-system"}`: 409, `{"name":"Bad_Name"}`: 400} {
		if rec := f.do(f.admin, "POST", "/api/v1/admin/namespace-exclusions", body); rec.Code != code {
			t.Errorf("POST %s: %d, want %d", body, rec.Code, code)
		}
	}
	for _, ns := range []string{"platform", "kube-system", "netcheck"} {
		if rec := f.do(f.admin, "DELETE", "/api/v1/admin/namespace-exclusions/"+ns, ""); rec.Code != http.StatusConflict {
			t.Errorf("DELETE %s: %d", ns, rec.Code)
		}
	}

	// Include it again: available at once.
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/namespace-exclusions/payments", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("include: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "GET", "/api/v1/namespaces", ""); !strings.Contains(rec.Body.String(), `"payments"`) {
		t.Errorf("namespace not available again: %s", rec.Body)
	}
}

func hasAction(events []store.AuditEvent, action string) bool {
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}
