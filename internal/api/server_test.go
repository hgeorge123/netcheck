package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/scheduler"
	"github.com/hgeorge123/netcheck/internal/store"
)

type recordingStarter struct {
	mu      sync.Mutex
	started []string
	lim     *scheduler.Limiter
	hold    bool
}

func (r *recordingStarter) Start(run store.Run, _ probes.Spec) {
	r.mu.Lock()
	r.started = append(r.started, run.ID)
	r.mu.Unlock()
	if !r.hold {
		r.lim.Release(run.Namespace)
	}
}

type nsList struct {
	mu   sync.Mutex
	list []string
}

func (n *nsList) Available(context.Context) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.list...), nil
}

func (n *nsList) add(ns string) {
	n.mu.Lock()
	n.list = append(n.list, ns)
	n.mu.Unlock()
}

type fixture struct {
	t       *testing.T
	srv     *Server
	h       http.Handler
	store   *store.Store
	local   *auth.LocalAuth
	ns      *nsList
	starter *recordingStarter
	admin   string // session cookie values
	user    string
}

const (
	adminPass = "admin-initial-1"
	userTemp  = "user-temporary-1"
	userPass  = "user-final-pass-1"
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ns := &nsList{list: []string{"payments", "readonly", "secret"}}
	local := &auth.LocalAuth{Store: st, Namespaces: ns, SessionIdle: time.Hour, SessionMax: 12 * time.Hour, MaxFailures: 5,
		LockDuration: 15 * time.Minute, CookieSecure: true, LoginLimiter: auth.NewRateLimiter(1000, time.Minute)}
	if _, err := local.EnsureBootstrapAdmin(context.Background(), "admin", adminPass, false); err != nil {
		t.Fatal(err)
	}
	lim := scheduler.NewLimiter(3, 10)
	starter := &recordingStarter{lim: lim}
	web := t.TempDir()
	os.WriteFile(filepath.Join(web, "index.html"), []byte("<!doctype html><title>NetCheck</title>"), 0o600)
	srv := &Server{
		Store: st, Authn: local, Local: local, Authz: &auth.Authorizer{Source: ns}, ScopeMode: "all",
		Starter: starter, Limiter: lim,
		Policies: NewDestinationPolicies(probes.DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowHostnameSuffixes: []string{".svc.cluster.local"},
			AllowPorts: []probes.PortRange{{From: 80, To: 443}}}, probes.BuiltinDenyCIDRs, true),
		TrustedCAs: mustTrustedCAs(t, st),
		Proxies:    mustProxies(t, st),
		Retention:  NewRetentionSettings(15, 45),
		Limits:     probes.Limits{MaxChecks: 5, DefaultCheckTimeout: 5 * time.Second, MaxCheckTimeout: 10 * time.Second, MaxJobDuration: 60 * time.Second, MaxOutputBytes: 65536},
		ClusterID:  "lab", WebDir: web, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	f := &fixture{t: t, srv: srv, h: srv.Handler(), store: st, local: local, ns: ns, starter: starter}
	f.admin = f.login("admin", adminPass, http.StatusOK)
	// Admin creates a regular user restricted to two namespaces.
	rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"Bob","displayName":"Bob B","role":"user","password":"`+userTemp+`","namespaces":["payments","readonly"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	temp := f.login("bob", userTemp, http.StatusOK)
	if rec := f.do(temp, "POST", "/api/v1/auth/password", `{"currentPassword":"`+userTemp+`","newPassword":"`+userPass+`"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body)
	}
	f.user = temp
	return f
}

func (f *fixture) req(session, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) do(session, method, path, body string) *httptest.ResponseRecorder {
	return f.req(session, method, path, body, nil)
}

func (f *fixture) login(user, pass string, want int) string {
	f.t.Helper()
	rec := f.do("", "POST", "/api/v1/auth/login", `{"username":"`+user+`","password":"`+pass+`"}`)
	if rec.Code != want {
		f.t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c.Value
		}
	}
	return ""
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Error ErrorBody }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not an error envelope: %s", rec.Body.String())
	}
	if body.Error.RequestID == "" {
		t.Error("error without requestId")
	}
	return body.Error.Code
}

const validRun = `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":443},{"method":"https","http":{"method":"HEAD"}}]}`

func TestLoginCookieAndLogout(t *testing.T) {
	f := newFixture(t)
	rec := f.do("", "POST", "/api/v1/auth/login", `{"username":"admin","password":"`+adminPass+`"}`)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("session cookie not hardened: %+v", cookie)
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Error("session token leaked in the response body")
	}
	if rec := f.do(cookie.Value, "POST", "/api/v1/auth/logout", "{}"); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := f.do(cookie.Value, "GET", "/api/v1/me", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("session still valid after logout: %d", rec.Code)
	}
	if rec := f.do("", "POST", "/api/v1/auth/login", `{"username":"admin","password":"wrong-password-1"}`); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "invalid_credentials" {
		t.Errorf("bad login: %d", rec.Code)
	}
	if rec := f.do("", "POST", "/api/v1/auth/login", `{"username":"ghost","password":"wrong-password-1"}`); errCode(t, rec) != "invalid_credentials" {
		t.Error("unknown user must get the same error as a bad password")
	}
}

func TestLoginIsCSRFProtected(t *testing.T) {
	f := newFixture(t)
	if rec := f.req("", "POST", "/api/v1/auth/login", `{"username":"admin","password":"x"}`, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin login: %d", rec.Code)
	}
}

func TestTemporaryPasswordBlocksEverythingElse(t *testing.T) {
	f := newFixture(t)
	f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"carol","role":"user","password":"carol-temp-pass1","allNamespaces":true}`)
	temp := f.login("carol", "carol-temp-pass1", http.StatusOK)
	var me map[string]any
	rec := f.do(temp, "GET", "/api/v1/me", "")
	json.Unmarshal(rec.Body.Bytes(), &me)
	if rec.Code != 200 || me["mustChangePassword"] != true {
		t.Fatalf("me: %d %v", rec.Code, me)
	}
	for _, p := range []string{"/api/v1/namespaces", "/api/v1/runs", "/api/v1/probes/catalog"} {
		if rec := f.do(temp, "GET", p, ""); rec.Code != http.StatusForbidden || errCode(t, rec) != "password_change_required" {
			t.Errorf("%s with temporary password: %d", p, rec.Code)
		}
	}
	if rec := f.do(temp, "POST", "/api/v1/runs", validRun); rec.Code != http.StatusForbidden {
		t.Errorf("run with temporary password: %d", rec.Code)
	}
	// The UI language can be chosen before the first password change.
	if rec := f.do(temp, "PUT", "/api/v1/me/preferences", `{"language":"es"}`); rec.Code != http.StatusOK {
		t.Errorf("language with temporary password: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(temp, "POST", "/api/v1/auth/password", `{"currentPassword":"carol-temp-pass1","newPassword":"short"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("weak new password: %d", rec.Code)
	}
}

func TestRoleSeparation(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/admin/users", ""},
		{"POST", "/api/v1/admin/users", `{"username":"eve","role":"admin","password":"eve-password-12","allNamespaces":true}`},
		{"GET", "/api/v1/admin/namespaces", ""},
	} {
		if rec := f.do(f.user, c.method, c.path, c.body); rec.Code != http.StatusForbidden || errCode(t, rec) != "admin_required" {
			t.Errorf("user %s %s: %d", c.method, c.path, rec.Code)
		}
	}
	var me struct {
		Role       string
		Namespaces []auth.NamespaceGrant
	}
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/me", "").Body.Bytes(), &me)
	if me.Role != "user" || len(me.Namespaces) != 2 {
		t.Errorf("user me = %+v", me)
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/me", "").Body.Bytes(), &me)
	if me.Role != "admin" || len(me.Namespaces) != 3 {
		t.Errorf("admin me = %+v", me)
	}
}

func TestAdminUserLifecycle(t *testing.T) {
	f := newFixture(t)
	var list struct{ Items []UserView }
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/users", "").Body.Bytes(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("users = %+v", list.Items)
	}
	var bob UserView
	for _, u := range list.Items {
		if u.Username == "bob" {
			bob = u
		}
	}
	if strings.Contains(f.do(f.admin, "GET", "/api/v1/admin/users", "").Body.String(), "argon2") {
		t.Fatal("password hashes exposed by the API")
	}
	// Unknown namespace and weak password are rejected.
	if rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"dave","role":"user","password":"dave-password-1","namespaces":["kube-system"]}`); rec.Code != 400 {
		t.Errorf("unknown namespace: %d", rec.Code)
	}
	if rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"dave","role":"user","password":"weak","allNamespaces":true}`); rec.Code != 400 {
		t.Errorf("weak password: %d", rec.Code)
	}
	if rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"BOB","role":"user","password":"dave-password-1","allNamespaces":true}`); rec.Code != 400 {
		t.Errorf("duplicate: %d", rec.Code)
	}
	// Grant all namespaces: bob immediately sees a namespace created later.
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/users/"+bob.ID, `{"displayName":"Bob","role":"user","allNamespaces":true}`); rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	f.ns.add("created-later")
	if rec := f.do(f.user, "GET", "/api/v1/namespaces", ""); !strings.Contains(rec.Body.String(), "created-later") {
		t.Errorf("all-namespaces user does not see the new namespace: %s", rec.Body)
	}
	// Reset password revokes bob's session.
	if rec := f.do(f.admin, "POST", "/api/v1/admin/users/"+bob.ID+"/password", `{"password":"bob-reset-pass-1"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d", rec.Code)
	}
	if rec := f.do(f.user, "GET", "/api/v1/me", ""); rec.Code != http.StatusUnauthorized {
		t.Error("reset must revoke sessions")
	}
	if rec := f.do(f.admin, "POST", "/api/v1/admin/users/"+bob.ID+"/unlock", "{}"); rec.Code != http.StatusNoContent {
		t.Errorf("unlock: %d", rec.Code)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/users/"+bob.ID, `{"username":"renamed","role":"user","allNamespaces":true}`); rec.Code != 400 {
		t.Errorf("rename must be refused: %d", rec.Code)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/users/"+bob.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/users/"+bob.ID, ""); rec.Code != 404 {
		t.Errorf("deleted user: %d", rec.Code)
	}
	// Self protection.
	var me struct{ ID string }
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/me", "").Body.Bytes(), &me)
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/users/"+me.ID, ""); rec.Code != http.StatusConflict {
		t.Errorf("self delete: %d", rec.Code)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/namespaces", ""); !strings.Contains(rec.Body.String(), `"mode":"all"`) {
		t.Errorf("admin namespaces: %s", rec.Body)
	}
}

func TestCreateRunAcceptedAndPersistedBeforeStart(t *testing.T) {
	f := newFixture(t)
	rec := f.do(f.user, "POST", "/api/v1/runs", validRun)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
	}
	var resp struct{ ID, Status string }
	json.Unmarshal(rec.Body.Bytes(), &resp)
	run, execs, err := f.store.GetRun(context.Background(), resp.ID)
	if err != nil || run.Status != "queued" || run.ActorDisplay != "Bob B" || len(execs) != 2 {
		t.Fatalf("persisted = %+v %v %v", run, execs, err)
	}
	if len(f.starter.started) != 1 {
		t.Error("executor not started")
	}
}

func TestCreateRunRejections(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"not assigned", `{"namespace":"secret","target":"10.1.2.3","checks":[{"method":"tcp","port":443}]}`, 403, "namespace_forbidden"},
		{"unknown ns", `{"namespace":"kube-system","target":"10.1.2.3","checks":[{"method":"tcp","port":443}]}`, 403, "namespace_forbidden"},
		{"metadata", `{"namespace":"payments","target":"169.254.169.254","checks":[{"method":"http"}]}`, 403, "destination_denied"},
		{"port", `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":22}]}`, 403, "destination_denied"},
		{"validation", `{"namespace":"payments","target":"-oProxyCommand=x","checks":[{"method":"tcp","port":443}]}`, 400, "validation_failed"},
		{"bad method", `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"bash"}]}`, 400, "validation_failed"},
		{"unknown field", `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":443}],"command":"id"}`, 400, "invalid_json"},
		{"two objects", validRun + validRun, 400, "invalid_json"},
		{"too big", `{"namespace":"payments","target":"` + strings.Repeat("a", 20000) + `"}`, 400, "invalid_json"},
	}
	for _, c := range cases {
		rec := f.do(f.user, "POST", "/api/v1/runs", c.body)
		if rec.Code != c.status || errCode(t, rec) != c.code {
			t.Errorf("%s: status=%d body=%s", c.name, rec.Code, rec.Body)
		}
	}
	if len(f.starter.started) != 0 {
		t.Error("rejected requests must not start runs")
	}
}

func TestCSRFProtection(t *testing.T) {
	f := newFixture(t)
	for name, hdr := range map[string]map[string]string{
		"form":       {"Content-Type": "application/x-www-form-urlencoded"},
		"cross-site": {"Sec-Fetch-Site": "cross-site"},
		"same-site":  {"Sec-Fetch-Site": "same-site"},
		"origin":     {"Origin": "https://evil.example"},
	} {
		if rec := f.req(f.user, "POST", "/api/v1/runs", validRun, hdr); rec.Code != 403 && rec.Code != 415 {
			t.Errorf("%s: status = %d", name, rec.Code)
		}
	}
	if rec := f.req(f.admin, "DELETE", "/api/v1/admin/users/whatever", "", map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin DELETE: %d", rec.Code)
	}
	if rec := f.req(f.user, "POST", "/api/v1/runs", validRun, map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}); rec.Code != http.StatusAccepted {
		t.Errorf("same-origin request rejected: %d %s", rec.Code, rec.Body)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	f := newFixture(t)
	f.starter.hold = true
	for i := 0; i < 3; i++ {
		if rec := f.do(f.user, "POST", "/api/v1/runs", validRun); rec.Code != http.StatusAccepted {
			t.Fatalf("run %d: %d", i, rec.Code)
		}
	}
	if rec := f.do(f.user, "POST", "/api/v1/runs", validRun); rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "concurrency_limit" {
		t.Fatalf("status = %d", rec.Code)
	}
}

func seedRun(t *testing.T, st *store.Store, id, ns string) { seedRunBy(t, st, id, ns, "x") }

func seedRunBy(t *testing.T, st *store.Store, id, ns, actorID string) {
	t.Helper()
	err := st.CreateRun(context.Background(), store.Run{ID: id, CreatedAt: time.Now(), ActorID: actorID, Namespace: ns, ClusterID: "lab",
		Target: "10.0.0.1", Status: "queued", RequestJSON: "{}", SpecJSON: "{}"},
		[]store.Execution{{ID: id + "-1", Seq: 1, CheckID: "1-tcp", Method: "tcp", Status: "queued"}}, store.AuditEvent{Action: "seed", Outcome: "ok"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunReadIsolation(t *testing.T) {
	f := newFixture(t)
	bob, err := f.store.GetUserByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	// Each user only reads the tests they started, even in a namespace they
	// share with others; administrators read every test.
	seedRunBy(t, f.store, "aaaaaaaaaaaaaaaa", "payments", bob.ID)
	seedRunBy(t, f.store, "bbbbbbbbbbbbbbbb", "payments", "u-someone-else")
	seedRunBy(t, f.store, "cccccccccccccccc", "secret", "u-someone-else")
	if rec := f.do(f.user, "GET", "/api/v1/runs/aaaaaaaaaaaaaaaa", ""); rec.Code != 200 {
		t.Errorf("own run: %d", rec.Code)
	}
	missing := f.do(f.user, "GET", "/api/v1/runs/dddddddddddddddd", "")
	for _, id := range []string{"bbbbbbbbbbbbbbbb", "cccccccccccccccc"} {
		other := f.do(f.user, "GET", "/api/v1/runs/"+id, "")
		if other.Code != 404 || missing.Code != 404 || errCode(t, other) != errCode(t, missing) {
			t.Errorf("another user's run %s must look missing: %d vs %d", id, other.Code, missing.Code)
		}
	}
	if rec := f.do(f.admin, "GET", "/api/v1/runs/bbbbbbbbbbbbbbbb", ""); rec.Code != 200 {
		t.Errorf("admin must see every run: %d", rec.Code)
	}
	var list struct{ Items []RunSummary }
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/runs?pageSize=50", "").Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].ID != "aaaaaaaaaaaaaaaa" {
		t.Fatalf("user list leaked: %+v", list.Items)
	}
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/runs?pageSize=50&namespace=payments", "").Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Errorf("namespace filter leaked other users' runs: %+v", list.Items)
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/runs?pageSize=50", "").Body.Bytes(), &list)
	if len(list.Items) != 3 {
		t.Errorf("admin list = %d", len(list.Items))
	}
	var stats struct{ Total int }
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/stats", "").Body.Bytes(), &stats)
	if stats.Total != 1 {
		t.Errorf("user dashboard counts other users' runs: %d", stats.Total)
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/stats", "").Body.Bytes(), &stats)
	if stats.Total != 3 {
		t.Errorf("admin dashboard = %d", stats.Total)
	}
	for _, q := range []string{"pageSize=0", "pageSize=1000", "status=hacked", "from=yesterday", "cursor=***"} {
		if rec := f.do(f.user, "GET", "/api/v1/runs?"+q, ""); rec.Code != 400 {
			t.Errorf("query %s: status %d", q, rec.Code)
		}
	}
}

func TestForgedIdentityHeadersAreIgnored(t *testing.T) {
	f := newFixture(t)
	hdr := map[string]string{"X-Auth-Request-User": "admin", "X-Forwarded-User": "admin", "X-Auth-Request-Groups": "admins"}
	if rec := f.req("", "GET", "/api/v1/me", "", hdr); rec.Code != http.StatusUnauthorized {
		t.Errorf("headers without session: %d", rec.Code)
	}
	if rec := f.req(f.user, "GET", "/api/v1/admin/users", "", hdr); rec.Code != http.StatusForbidden {
		t.Errorf("headers escalated a user: %d", rec.Code)
	}
}

func TestHeadersHealthAndStatic(t *testing.T) {
	f := newFixture(t)
	rec := f.req("", "GET", "/api/v1/me", "", map[string]string{"X-Request-Id": "bad id with spaces"})
	if rec.Code != 401 || strings.Contains(rec.Header().Get("X-Request-Id"), " ") {
		t.Fatalf("status = %d id = %q", rec.Code, rec.Header().Get("X-Request-Id"))
	}
	for _, hdr := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("missing header %s", hdr)
		}
	}
	if rec := f.do("", "GET", "/readyz", ""); rec.Code != 200 {
		t.Errorf("readyz = %d", rec.Code)
	}
	if rec := f.do("", "GET", "/runs/abc", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "NetCheck") {
		t.Errorf("spa fallback: %d", rec.Code)
	}
	if rec := f.do(f.user, "GET", "/api/v1/nope", ""); rec.Code != 404 {
		t.Errorf("api 404: %d", rec.Code)
	}
}

func TestPreferencesStatsSessionsAndSystem(t *testing.T) {
	f := newFixture(t)
	f.srv.Version = store.AppVersion{Version: "1.2.3", Commit: "abc"}
	f.store.RecordVersion(context.Background(), f.srv.Version, time.Now())

	if rec := f.do(f.user, "PUT", "/api/v1/me/preferences", `{"language":"es"}`); rec.Code != 200 {
		t.Fatalf("preferences: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "PUT", "/api/v1/me/preferences", `{"language":"fr"}`); rec.Code != 400 {
		t.Errorf("unsupported language: %d", rec.Code)
	}
	var me struct{ Language, Version string }
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/me", "").Body.Bytes(), &me)
	if me.Language != "es" || me.Version != "1.2.3" {
		t.Errorf("me = %+v", me)
	}

	f.do(f.user, "POST", "/api/v1/runs", validRun)
	var st struct {
		Total    int
		ByStatus map[string]int
	}
	json.Unmarshal(f.do(f.user, "GET", "/api/v1/stats?hours=24", "").Body.Bytes(), &st)
	if st.Total != 1 || st.ByStatus["queued"] != 1 {
		t.Errorf("stats = %+v", st)
	}

	var sessions struct {
		Items          []SessionView
		ConnectedUsers int
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/sessions", "").Body.Bytes(), &sessions)
	if sessions.ConnectedUsers != 2 || len(sessions.Items) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	var mine, other SessionView
	for _, s := range sessions.Items {
		if s.Current {
			mine = s
		} else {
			other = s
		}
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/sessions/"+mine.ID, ""); rec.Code != 409 {
		t.Errorf("revoking own session: %d", rec.Code)
	}
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/sessions/"+other.ID, ""); rec.Code != 204 {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := f.do(f.user, "GET", "/api/v1/me", ""); rec.Code != 401 {
		t.Errorf("revoked session still works: %d", rec.Code)
	}
	if rec := f.do(f.user, "GET", "/api/v1/admin/sessions", ""); rec.Code != 401 && rec.Code != 403 {
		t.Errorf("non-admin sessions: %d", rec.Code)
	}

	var sys struct {
		Current VersionView
		History []VersionView
	}
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/system", "").Body.Bytes(), &sys)
	if sys.Current.Version != "1.2.3" || len(sys.History) != 1 {
		t.Errorf("system = %+v", sys)
	}
}

func TestNetcheckNamespaceRequiresFlag(t *testing.T) {
	f := newFixture(t)
	f.srv.Authz.OwnNamespace = "netcheck"
	body := `{"namespace":"netcheck","target":"10.1.2.3","checks":[{"method":"tcp","port":443}]}`
	if rec := f.do(f.admin, "POST", "/api/v1/runs", body); rec.Code != 403 {
		t.Errorf("admin without flag ran in the NetCheck namespace: %d", rec.Code)
	}
	var ns struct{ NetcheckNamespace string }
	json.Unmarshal(f.do(f.admin, "GET", "/api/v1/admin/namespaces", "").Body.Bytes(), &ns)
	if ns.NetcheckNamespace != "netcheck" {
		t.Errorf("admin namespaces = %+v", ns)
	}
	rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"ops","role":"user","password":"ops-temporary-1","namespaces":["payments"],"allowNetcheckNamespace":true}`)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"allowNetcheckNamespace":true`) {
		t.Fatalf("create flagged user: %d %s", rec.Code, rec.Body)
	}
	ops := f.login("ops", "ops-temporary-1", http.StatusOK)
	f.do(ops, "POST", "/api/v1/auth/password", `{"currentPassword":"ops-temporary-1","newPassword":"ops-final-pass-1"}`)
	if rec := f.do(ops, "GET", "/api/v1/namespaces", ""); !strings.Contains(rec.Body.String(), `"netcheck"`) {
		t.Errorf("flagged user does not see the NetCheck namespace: %s", rec.Body)
	}
	if rec := f.do(ops, "POST", "/api/v1/runs", body); rec.Code != 202 {
		t.Errorf("flagged user run: %d %s", rec.Code, rec.Body)
	}
}
