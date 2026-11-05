package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hgeorge123/netcheck/internal/auth"
)

// rolesFixture wires the role holder like main does.
func rolesFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	roles, err := auth.LoadRoles(context.Background(), f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.Authz.Roles, f.local.Roles = roles, roles
	return f
}

func (f *fixture) createRole(body string) string {
	f.t.Helper()
	rec := f.do(f.admin, "POST", "/api/v1/admin/roles", body)
	var v RoleView
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		f.t.Fatalf("create role: %d %s", rec.Code, rec.Body)
	}
	return v.ID
}

func (f *fixture) userID(name string) string {
	f.t.Helper()
	var list struct {
		Items []struct{ ID, Username string } `json:"items"`
	}
	_ = json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/users", "").Body.Bytes(), &list)
	for _, u := range list.Items {
		if u.Username == name {
			return u.ID
		}
	}
	f.t.Fatalf("user %s not found", name)
	return ""
}

func (f *fixture) setRole(user, role, namespaces string) {
	f.t.Helper()
	rec := f.do(f.admin, "PUT", "/api/v1/admin/users/"+f.userID(user), `{"displayName":"`+user+`","role":"`+role+`","namespaces":`+namespaces+`}`)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("set role: %d %s", rec.Code, rec.Body)
	}
}

func TestCustomRoleLimitsChecksTokensAndProxies(t *testing.T) {
	f := rolesFixture(t)
	ping := f.createRole(`{"name":"Ping only","description":"Network on-call","permissions":["check.ping","check.tcp","tokens.create","check.tcp"]}`)
	f.setRole("bob", ping, `["payments"]`)

	// The namespaces say what the role allows in each.
	rec := f.do(f.user, "GET", "/api/v1/namespaces", "")
	if !strings.Contains(rec.Body.String(), `"checks":["tcp","ping"],"firewallMode":false`) {
		t.Errorf("namespaces: %s", rec.Body)
	}
	// HTTPS is not in the role: refused naming the check; TCP alone runs.
	rec = f.do(f.user, "POST", "/api/v1/runs", validRun)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != "check_not_allowed" || !strings.Contains(rec.Body.String(), `"field":"checks[1]"`) {
		t.Errorf("run with https: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":443}]}`); rec.Code != http.StatusAccepted {
		t.Errorf("tcp run: %d %s", rec.Code, rec.Body)
	}
	// No personal proxies in this role; tokens are.
	if rec := f.do(f.user, "POST", "/api/v1/proxies", `{"name":"mine","host":"10.0.0.9","port":3128}`); rec.Code != http.StatusForbidden || errCode(t, rec) != "permission_required" {
		t.Errorf("personal proxy: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "POST", "/api/v1/me/tokens", `{"name":"ci","expiresInDays":30}`); rec.Code != http.StatusCreated {
		t.Errorf("token: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "GET", "/api/v1/me", ""); !strings.Contains(rec.Body.String(), `"permissions":["check.tcp","check.ping","tokens.create"]`) || !strings.Contains(rec.Body.String(), `"roleName":"Ping only"`) {
		t.Errorf("me: %s", rec.Body)
	}

	// A role in use cannot be deleted; built-in roles cannot be changed.
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/roles/"+ping, ""); rec.Code != http.StatusConflict || errCode(t, rec) != "role_in_use" {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/roles/user", `{"name":"User","permissions":[]}`); rec.Code != http.StatusConflict {
		t.Errorf("update built-in: %d %s", rec.Code, rec.Body)
	}
	f.setRole("bob", "user", `["payments"]`)
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/roles/"+ping, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	// Users only get existing roles.
	rec = f.do(f.admin, "PUT", "/api/v1/admin/users/"+f.userID("bob"), `{"displayName":"Bob","role":"`+ping+`","namespaces":["payments"]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "role_invalid") {
		t.Errorf("deleted role given: %d %s", rec.Code, rec.Body)
	}
}

func TestRoleValidation(t *testing.T) {
	f := rolesFixture(t)
	f.createRole(`{"name":"Auditors","permissions":["runs.all"]}`)
	for body, code := range map[string]string{
		`{"name":"","permissions":[]}`:                                  "role_name_invalid",
		`{"name":"x","permissions":["admin.users"]}`:                    "unknown_permission",
		`{"name":"auditors","permissions":[]}`:                          "role_exists",
		`{"name":"x","description":"` + strings.Repeat("d", 300) + `"}`: "role_description_invalid",
	} {
		if rec := f.do(f.admin, "POST", "/api/v1/admin/roles", body); rec.Code < 400 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%.40s: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := f.do(f.user, "GET", "/api/v1/admin/roles", ""); rec.Code != http.StatusForbidden {
		t.Errorf("user lists roles: %d", rec.Code)
	}
}

func TestRunsAllShowsTheTestsOfItsNamespaces(t *testing.T) {
	f := rolesFixture(t)
	// The administrator runs a test in payments and one in secret.
	for _, ns := range []string{"payments", "secret"} {
		if rec := f.do(f.admin, "POST", "/api/v1/runs", strings.Replace(validRun, "payments", ns, 1)); rec.Code != http.StatusAccepted {
			t.Fatalf("admin run in %s: %d %s", ns, rec.Code, rec.Body)
		}
	}
	auditor := f.createRole(`{"name":"Auditor","permissions":["runs.all","check.tcp"]}`)
	f.setRole("bob", auditor, `["payments"]`)
	rec := f.do(f.user, "GET", "/api/v1/runs", "")
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `"namespace":"payments"`) != 1 || strings.Contains(rec.Body.String(), `"namespace":"secret"`) {
		t.Errorf("auditor history: %d %s", rec.Code, rec.Body)
	}
	// Effective permissions name the grant and what it allows.
	rec = f.do(f.admin, "GET", "/api/v1/admin/users/"+f.userID("bob")+"/permissions", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"roleName":"Auditor"`) || !strings.Contains(rec.Body.String(), `"source":"account"`) ||
		!strings.Contains(rec.Body.String(), `"name":"payments","canRun":true,"checks":["tcp"]`) {
		t.Errorf("permissions: %d %s", rec.Code, rec.Body)
	}
}
