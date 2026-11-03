package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/store"
)

type staticNS []string

func (s staticNS) Available(context.Context) ([]string, error) { return s, nil }

func newLocal(t *testing.T) (*LocalAuth, *time.Time) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	l := &LocalAuth{Store: st, Namespaces: staticNS{"orders", "payments", "shipping"}, SessionIdle: time.Hour, SessionMax: 12 * time.Hour,
		MaxFailures: 3, LockDuration: 15 * time.Minute, CookieSecure: true, LoginLimiter: NewRateLimiter(100, time.Minute),
		Now: func() time.Time { return now }}
	return l, &now
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %q %v", h, err)
	}
	if ok, _ := VerifyPassword("correct horse battery", h); !ok {
		t.Error("valid password rejected")
	}
	if ok, _ := VerifyPassword("wrong password!!", h); ok {
		t.Error("invalid password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("salt not random")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$a$b", "$argon2id$v=19$m=99999999,t=2,p=1$YQ$YQ"} {
		if ok, err := VerifyPassword("x", bad); ok || err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := map[string]bool{"short": false, "alice-alice1": true, "ALICEALICE12": true, strings.Repeat("x", 129): false, "            ": false}
	for pw, ok := range cases {
		if err := ValidatePassword(pw, "bob"); (err == nil) != ok {
			t.Errorf("ValidatePassword(%q) = %v", pw, err)
		}
	}
	if ValidatePassword("aliceinwonder", "AliceInWonder") == nil {
		t.Error("password equal to username accepted")
	}
	if g := GeneratePassword(); len(g) != 20 || ValidatePassword(g, "admin") != nil {
		t.Errorf("generated password %q", g)
	}
}

func login(t *testing.T, l *LocalAuth, user, pw string) (string, Identity, error) {
	t.Helper()
	return l.Login(context.Background(), user, pw, "10.0.0.1", "test-agent", "req")
}

func requestWithCookie(token string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/me", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	return r
}

func TestBootstrapLoginSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	l, now := newLocal(t)
	created, err := l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", true)
	if err != nil || !created {
		t.Fatalf("bootstrap: %v %v", created, err)
	}
	if again, err := l.EnsureBootstrapAdmin(ctx, "admin", "other-pass-12345", true); err != nil || again {
		t.Fatal("bootstrap must not run twice nor overwrite the admin")
	}
	token, id, err := login(t, l, " ADMIN ", "initial-pass-123")
	if err != nil || !id.IsAdmin() || !id.MustChangePassword {
		t.Fatalf("login: %+v %v", id, err)
	}
	got, err := l.Authenticate(requestWithCookie(token))
	if err != nil || got.ID != id.ID {
		t.Fatalf("authenticate: %v", err)
	}
	// Idle timeout.
	*now = now.Add(2 * time.Hour)
	if _, err := l.Authenticate(requestWithCookie(token)); err != ErrUnauthenticated {
		t.Error("idle session must expire")
	}
	if _, err := l.Authenticate(requestWithCookie("forged-token")); err != ErrUnauthenticated {
		t.Error("unknown token accepted")
	}
	if _, err := l.Authenticate(httptest.NewRequest("GET", "/", nil)); err != ErrUnauthenticated {
		t.Error("missing cookie accepted")
	}
}

func TestLoginFailuresLockAndAreGeneric(t *testing.T) {
	ctx := context.Background()
	l, now := newLocal(t)
	l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", false)
	if _, _, err := login(t, l, "nobody", "whatever-pass-1"); err != ErrInvalidCredentials {
		t.Errorf("unknown user err = %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := login(t, l, "admin", "bad-password-xx"); err != ErrInvalidCredentials {
			t.Fatalf("bad password err = %v", err)
		}
	}
	// Locked: even the right password fails with the same generic error.
	if _, _, err := login(t, l, "admin", "initial-pass-123"); err != ErrInvalidCredentials {
		t.Errorf("locked account err = %v", err)
	}
	*now = now.Add(16 * time.Minute)
	if _, _, err := login(t, l, "admin", "initial-pass-123"); err != nil {
		t.Errorf("lock must expire: %v", err)
	}
}

func TestLoginRateLimitPerIP(t *testing.T) {
	l, _ := newLocal(t)
	l.LoginLimiter = NewRateLimiter(2, time.Minute)
	login(t, l, "x", "y")
	login(t, l, "x", "y")
	if _, _, err := login(t, l, "x", "y"); err != ErrRateLimited {
		t.Errorf("err = %v, want rate limited", err)
	}
}

func TestUserAdministration(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", false)
	_, admin, _ := login(t, l, "admin", "initial-pass-123")

	bad := []UserInput{
		{Username: "ab", Role: "user", Password: "temporary-pass-1", Namespaces: []string{"orders"}},
		{Username: "Bad User", Role: "user", Password: "temporary-pass-1", Namespaces: []string{"orders"}},
		{Username: "carol", Role: "root", Password: "temporary-pass-1", Namespaces: []string{"orders"}},
		{Username: "carol", Role: "user", Password: "short", Namespaces: []string{"orders"}},
		{Username: "carol", Role: "user", Password: "temporary-pass-1"},
		{Username: "carol", Role: "user", Password: "temporary-pass-1", Namespaces: []string{"kube-system"}},
	}
	for _, in := range bad {
		var ie InputError
		if _, err := l.CreateUser(ctx, admin, in, "r"); !errors.As(err, &ie) {
			t.Errorf("CreateUser(%+v) err = %v, want InputError", in, err)
		}
	}
	carol, err := l.CreateUser(ctx, admin, UserInput{Username: "Carol", DisplayName: "Carol C", Role: "user", Password: "temporary-pass-1",
		Namespaces: []string{"orders"}}, "r")
	if err != nil || carol.Username != "carol" || !carol.MustChangePassword {
		t.Fatalf("create: %+v %v", carol, err)
	}
	if _, err := l.CreateUser(ctx, admin, UserInput{Username: "CAROL", Role: "user", Password: "temporary-pass-1", AllNamespaces: true}, "r"); err == nil {
		t.Error("duplicate username accepted")
	}
	// The NetCheck namespace checkbox alone is a valid scope.
	if u, err := l.CreateUser(ctx, admin, UserInput{Username: "ops", Role: "user", Password: "temporary-pass-1", AllowNetcheckNamespace: true}, "r"); err != nil ||
		!u.AllowNetcheckNamespace {
		t.Errorf("user scoped only to the NetCheck namespace: %+v %v", u, err)
	}

	// Carol logs in with the temporary password and must change it.
	tok, cid, err := login(t, l, "carol", "temporary-pass-1")
	if err != nil || !cid.MustChangePassword {
		t.Fatalf("carol login: %+v %v", cid, err)
	}
	if err := l.ChangeOwnPassword(ctx, cid, "wrong-current-1", "carol-new-pass-1", "r"); err == nil {
		t.Error("wrong current password accepted")
	}
	if err := l.ChangeOwnPassword(ctx, cid, "temporary-pass-1", "carol-new-pass-1", "r"); err != nil {
		t.Fatal(err)
	}
	if after, err := l.Authenticate(requestWithCookie(tok)); err != nil || after.MustChangePassword {
		t.Errorf("own session must survive the change and flag cleared: %+v %v", after, err)
	}

	// Admin resets Carol's password: all her sessions die, must change again.
	if err := l.ResetPassword(ctx, admin, carol.ID, "admin-chosen-12", "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Authenticate(requestWithCookie(tok)); err != ErrUnauthenticated {
		t.Error("reset must revoke sessions")
	}
	if _, cid, _ = login(t, l, "carol", "admin-chosen-12"); !cid.MustChangePassword {
		t.Error("reset password must be temporary")
	}

	// Switch Carol to all namespaces, then disable her.
	upd, err := l.UpdateUser(ctx, admin, carol.ID, UserInput{DisplayName: "Carol", Role: "user", AllNamespaces: true, Namespaces: []string{"orders"}}, "r")
	if err != nil || !upd.AllNamespaces || len(upd.Namespaces) != 0 {
		t.Fatalf("update: %+v %v", upd, err)
	}
	if _, err := l.UpdateUser(ctx, admin, carol.ID, UserInput{Role: "user", AllNamespaces: true, Disabled: true}, "r"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := login(t, l, "carol", "admin-chosen-12"); err != ErrInvalidCredentials {
		t.Error("disabled user logged in")
	}

	// Self-protection.
	if _, err := l.UpdateUser(ctx, admin, admin.ID, UserInput{Role: "user", AllNamespaces: true}, "r"); err != ErrForbiddenSelf {
		t.Errorf("self demotion err = %v", err)
	}
	if err := l.DeleteUser(ctx, admin, admin.ID, "r"); err != ErrForbiddenSelf {
		t.Errorf("self delete err = %v", err)
	}
	if err := l.DeleteUser(ctx, admin, carol.ID, "r"); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverBootstrapAdmin(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", false)
	// The admin forgets the password and locks the account.
	for i := 0; i < 3; i++ {
		login(t, l, "admin", "forgotten-pass-x")
	}
	if err := l.RecoverBootstrapAdmin(ctx, "admin", "recovery-pass-123"); err != nil {
		t.Fatal(err)
	}
	_, id, err := login(t, l, "admin", "recovery-pass-123")
	if err != nil || !id.IsAdmin() || !id.MustChangePassword {
		t.Fatalf("recovered admin: %+v %v", id, err)
	}
	evs, _ := l.Store.ListAudit(ctx, "")
	found := false
	for _, ev := range evs {
		found = found || ev.Action == "user.recovery"
	}
	if !found {
		t.Error("recovery not audited")
	}
}

func TestBootstrapPasswordStale(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	if stale, err := l.BootstrapPasswordStale(ctx, "admin", "initial-pass-123"); err != nil || stale {
		t.Fatalf("no admin yet: %v %v", stale, err)
	}
	l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", true)
	if stale, err := l.BootstrapPasswordStale(ctx, "admin", "initial-pass-123"); err != nil || stale {
		t.Fatalf("Secret matches: %v %v", stale, err)
	}
	// The Secret was recreated with a new password after the admin existed.
	if stale, err := l.BootstrapPasswordStale(ctx, " ADMIN ", "regenerated-pass-1"); err != nil || !stale {
		t.Fatalf("Secret regenerated: %v %v", stale, err)
	}
	// Once the admin chose a password, the Secret no longer matters.
	_, id, _ := login(t, l, "admin", "initial-pass-123")
	if err := l.ChangeOwnPassword(ctx, id, "initial-pass-123", "chosen-pass-12345", "r"); err != nil {
		t.Fatal(err)
	}
	if stale, err := l.BootstrapPasswordStale(ctx, "admin", "regenerated-pass-1"); err != nil || stale {
		t.Fatalf("password already changed: %v %v", stale, err)
	}
}

func TestAuthorizerDynamicAllNamespaces(t *testing.T) {
	src := &mutableNS{list: []string{"orders", "payments"}}
	a := &Authorizer{Source: src}
	ctx := context.Background()
	all := Identity{ID: "1", Role: RoleUser, AllNamespaces: true}
	some := Identity{ID: "2", Role: RoleUser, Namespaces: []string{"orders", "gone"}}
	none := Identity{ID: "3", Role: RoleUser}

	src.list = append(src.list, "created-later")
	if ok, _ := a.CanRun(ctx, all, "created-later"); !ok {
		t.Error("all-namespaces user must see namespaces created later")
	}
	if ok, _ := a.CanRun(ctx, some, "created-later"); ok {
		t.Error("restricted user must not see new namespaces")
	}
	g, _ := a.Grants(ctx, some)
	if len(g) != 1 || g[0].Name != "orders" {
		t.Errorf("restricted grants = %v (deleted namespaces are not runnable)", g)
	}
	if g, _ := a.Grants(ctx, none); len(g) != 0 {
		t.Error("user without namespaces must see nothing")
	}
	if !a.CanView(some, "gone") || a.CanView(some, "payments") || !a.CanView(all, "anything") {
		t.Error("view scope wrong")
	}
	if ok, _ := a.CanRun(ctx, Identity{Role: RoleAdmin}, "payments"); !ok {
		t.Error("admin must run everywhere available")
	}
}

type mutableNS struct{ list []string }

func (m *mutableNS) Available(context.Context) ([]string, error) { return m.list, nil }

func TestClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if ip := ClientIP(r, trusted); ip != "203.0.113.9" {
		t.Errorf("untrusted peer XFF honoured: %s", ip)
	}
	r.RemoteAddr = "10.1.1.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.2.2.2")
	if ip := ClientIP(r, trusted); ip != "198.51.100.7" {
		t.Errorf("client ip = %s", ip)
	}
}

func TestNetcheckNamespaceOnlyWithFlag(t *testing.T) {
	ctx := context.Background()
	a := &Authorizer{Source: &mutableNS{list: []string{"orders", "payments"}}, OwnNamespace: "netcheck"}
	for _, id := range []Identity{{Role: RoleAdmin}, {Role: RoleUser, AllNamespaces: true}} {
		if ok, _ := a.CanRun(ctx, id, "netcheck"); ok {
			t.Errorf("%+v can use the NetCheck namespace without the flag", id)
		}
	}
	flagged := Identity{Role: RoleUser, Namespaces: []string{"orders"}, AllowNetcheckNamespace: true}
	if ok, _ := a.CanRun(ctx, flagged, "netcheck"); !ok {
		t.Error("flagged user cannot use the NetCheck namespace")
	}
	if !a.CanView(flagged, "netcheck") {
		t.Error("flagged user cannot read NetCheck namespace history")
	}
}

func TestLanguagePasswordCodesAndSessions(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	l.EnsureBootstrapAdmin(ctx, "admin", "initial-pass-123", false)
	_, admin, _ := login(t, l, "admin", "initial-pass-123")
	if admin.Language != "en" {
		t.Errorf("default language = %q", admin.Language)
	}
	if err := l.SetLanguage(ctx, admin, "es"); err != nil {
		t.Fatal(err)
	}
	var ie InputError
	if err := l.SetLanguage(ctx, admin, "fr"); !errors.As(err, &ie) || ie.Code != "language_invalid" {
		t.Errorf("unsupported language err = %v", err)
	}
	tok, again, _ := login(t, l, "admin", "initial-pass-123")
	if again.Language != "es" {
		t.Errorf("language not remembered: %q", again.Language)
	}
	if _, err := l.CreateUser(ctx, admin, UserInput{Username: "weak", Role: "user", Password: "short", AllNamespaces: true}, "r"); !errors.As(err, &ie) || ie.Code != "password_too_short" {
		t.Errorf("weak password code = %+v", ie)
	}
	sessions, err := l.ActiveSessions(ctx)
	if err != nil || len(sessions) != 2 || sessions[0].UserAgent != "test-agent" || sessions[0].ClientIP != "10.0.0.1" {
		t.Fatalf("sessions = %+v %v", sessions, err)
	}
	current, _ := l.Authenticate(requestWithCookie(tok))
	cur, _ := l.Store.GetSession(ctx, current.SessionHash)
	if err := l.RevokeSession(ctx, current, cur.ID, "r"); err != ErrForbiddenSelf {
		t.Errorf("revoking own session err = %v", err)
	}
	for _, s := range sessions {
		if s.ID != cur.ID {
			if err := l.RevokeSession(ctx, current, s.ID, "r"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if left, _ := l.ActiveSessions(ctx); len(left) != 1 {
		t.Errorf("sessions after revoke = %d", len(left))
	}
}
