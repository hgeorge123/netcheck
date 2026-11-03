package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAPITokens(t *testing.T) {
	f := newFixture(t)
	for body, code := range map[string]string{
		`{"name":"","expiresInDays":30}`:    "token_name_invalid",
		`{"name":"ci","expiresInDays":0}`:   "token_expiry_invalid",
		`{"name":"ci","expiresInDays":400}`: "token_expiry_invalid",
	} {
		if rec := f.do(f.user, "POST", "/api/v1/me/tokens", body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	rec := f.do(f.user, "POST", "/api/v1/me/tokens", `{"name":"payments pipeline","expiresInDays":30}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		Token string    `json:"token"`
		Item  TokenView `json:"item"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !strings.HasPrefix(created.Token, "nck_") || created.Item.Prefix != created.Token[:8] {
		t.Fatalf("created = %+v", created)
	}

	bearer := map[string]string{"Authorization": "Bearer " + created.Token}
	// Allowed: profile, namespaces, catalog, runs.
	for _, p := range []string{"/api/v1/me", "/api/v1/namespaces", "/api/v1/probes/catalog", "/api/v1/runs"} {
		if rec := f.req("", "GET", p, "", bearer); rec.Code != http.StatusOK {
			t.Errorf("GET %s with token: %d %s", p, rec.Code, rec.Body)
		}
	}
	// Outside the scope: token management, admin, preferences, password.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/me/tokens", ""},
		{"POST", "/api/v1/me/tokens", `{"name":"x","expiresInDays":1}`},
		{"GET", "/api/v1/admin/users", ""},
		{"PUT", "/api/v1/me/preferences", `{"language":"es"}`},
		{"POST", "/api/v1/auth/password", `{"currentPassword":"a","newPassword":"b"}`},
	} {
		if rec := f.req("", c.method, c.path, c.body, bearer); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "token_scope") {
			t.Errorf("%s %s with token: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	for _, h := range []string{"Bearer nck_forged", "Bearer " + created.Token + "x", "Basic abc", created.Token} {
		if rec := f.req("", "GET", "/api/v1/me", "", map[string]string{"Authorization": h}); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: %d", h, rec.Code)
		}
	}

	// The owner sees it; another user cannot revoke it; an admin can list and revoke it.
	if rec := f.do(f.user, "GET", "/api/v1/me/tokens", ""); !strings.Contains(rec.Body.String(), "payments pipeline") || strings.Contains(rec.Body.String(), created.Token) {
		t.Errorf("list must show the token without its secret: %s", rec.Body)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/me/tokens/"+created.Item.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("revoking somebody else's token as own: %d", rec.Code)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/tokens", ""); !strings.Contains(rec.Body.String(), `"owner":"bob"`) {
		t.Errorf("admin list: %s", rec.Body)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/tokens/"+created.Item.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("admin revoke: %d", rec.Code)
	}
	if rec := f.req("", "GET", "/api/v1/me", "", bearer); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token still works: %d", rec.Code)
	}
}

func TestTokenScope(t *testing.T) {
	cases := map[string]bool{
		"GET /api/v1/runs/abcdef0123456789": true,
		"GET /api/v1/runs/x/y":              false,
		"POST /api/v1/runs":                 true,
		"DELETE /api/v1/runs/x":             false,
		"POST /api/v1/auth/logout":          false,
		"GET /api/v1/stats":                 false,
	}
	for c, want := range cases {
		parts := strings.SplitN(c, " ", 2)
		r, _ := http.NewRequest(parts[0], parts[1], nil)
		if got := tokenAllowed(r); got != want {
			t.Errorf("%s: allowed = %v", c, got)
		}
	}
}
