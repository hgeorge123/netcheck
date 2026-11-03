package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestProvidersAndDisabledSSO(t *testing.T) {
	f := newFixture(t)
	rec := f.do("", "GET", "/api/v1/auth/providers", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"oidc":{"enabled":false}}` {
		t.Fatalf("providers: %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/api/v1/auth/oidc/start", "/api/v1/auth/oidc/callback?code=x&state=y"} {
		if rec := f.do("", "GET", path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s without SSO: %d", path, rec.Code)
		}
	}
}

func TestAdminAccessRules(t *testing.T) {
	f := newFixture(t)
	body := `{"subjectType":"group","subject":"acme:payments","role":"user","namespaces":["payments"]}`
	if rec := f.do(f.user, "POST", "/api/v1/admin/access-rules", body); rec.Code != http.StatusForbidden {
		t.Errorf("user POST: %d", rec.Code)
	}
	rec := f.do(f.admin, "POST", "/api/v1/admin/access-rules", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created AccessRuleView
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || created.UpdatedBy != "admin" {
		t.Fatalf("created = %+v", created)
	}
	if rec := f.do(f.admin, "POST", "/api/v1/admin/access-rules", body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "rule_exists") {
		t.Errorf("duplicate: %d %s", rec.Code, rec.Body)
	}
	for bad, code := range map[string]string{
		`{"subjectType":"team","subject":"x","role":"user","allNamespaces":true}`:            "subject_type_invalid",
		`{"subjectType":"group","subject":"","role":"user","allNamespaces":true}`:            "subject_invalid",
		`{"subjectType":"authenticated","role":"user","namespaces":["does-not-exist"]}`:      "namespace_unavailable",
		`{"subjectType":"user","subject":"ana@acme.com","role":"root","allNamespaces":true}`: "role_invalid",
	} {
		if rec := f.do(f.admin, "POST", "/api/v1/admin/access-rules", bad); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	upd := `{"subjectType":"group","subject":"acme:payments","role":"admin","allNamespaces":true}`
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/access-rules/"+created.ID, upd); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"admin"`) {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}
	rec = f.do(f.admin, "GET", "/api/v1/admin/access-rules", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ssoEnabled":false`) || !strings.Contains(rec.Body.String(), "acme:payments") {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/access-rules/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/access-rules/"+created.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete again: %d", rec.Code)
	}
}
