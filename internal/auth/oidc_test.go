package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/hgeorge123/netcheck/internal/store"
)

// fakeProvider is a minimal OpenID provider: discovery, keys and a token
// endpoint that checks PKCE and returns an ID token signed with RSA.
type fakeProvider struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]codeGrant // code -> grant
	claims map[string]any       // claims of the next sign-in
}

type codeGrant struct{ challenge, nonce string }

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, codes: map[string]codeGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/auth",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		g, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		claims := p.claims
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		now := time.Now()
		c := map[string]any{"iss": p.srv.URL, "aud": "netcheck", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": g.nonce}
		for k, v := range claims {
			c[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": p.sign(t, c)})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

// authorize simulates the browser at the provider: it records the code for
// the PKCE challenge and nonce of the authorization request.
func (p *fakeProvider) authorize(t *testing.T, authURL string) (code, state string) {
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, p.srv.URL+"/auth") {
		t.Fatalf("redirected to %q", authURL)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("client_id") != "netcheck" {
		t.Fatalf("authorization request = %v", q)
	}
	code = randomString()
	p.mu.Lock()
	p.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	p.mu.Unlock()
	return code, q.Get("state")
}

func newOIDC(t *testing.T) (*OIDC, *fakeProvider) {
	t.Helper()
	l, _ := newLocal(t)
	l.Now = nil // tokens are validated against the real clock
	p := newFakeProvider(t)
	return &OIDC{Local: l, HTTPClient: p.srv.Client(), Config: OIDCConfig{Issuer: p.srv.URL, ClientID: "netcheck", ClientSecret: "s",
		RedirectURL: "https://netcheck.test/api/v1/auth/oidc/callback", Scopes: []string{"openid", "email", "groups"},
		UsernameClaim: "email", GroupsClaim: "groups"}}, p
}

// signIn runs start + provider + callback and returns the callback result.
func signIn(t *testing.T, o *OIDC, p *fakeProvider, claims map[string]any, tamper func(*http.Request)) (string, error) {
	t.Helper()
	p.mu.Lock()
	p.claims = claims
	p.mu.Unlock()
	rec := httptest.NewRecorder()
	if err := o.Start(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/start", nil)); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != oidcCookie || cookie.SameSite != http.SameSiteLaxMode || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("state cookie = %+v", cookie)
	}
	code, state := p.authorize(t, rec.Header().Get("Location"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	req.AddCookie(cookie)
	if tamper != nil {
		tamper(req)
	}
	return o.Callback(req, "10.0.0.1", "test", "req")
}

func TestOIDCSignInWithGroupRule(t *testing.T) {
	o, p := newOIDC(t)
	ctx := context.Background()
	admin := Identity{ID: "admin", Username: "admin"}
	if _, err := o.Local.SaveAccessRule(ctx, admin, "", AccessRuleInput{SubjectType: store.SubjectGroup, Subject: "acme:payments", Role: store.RoleUser,
		Namespaces: []string{"payments"}}, "r"); err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"sub": "u-123", "email": "Ana@Acme.com", "email_verified": true, "name": "Ana", "groups": []string{"acme:payments", "acme:all"}}
	token, err := signIn(t, o, p, claims, nil)
	if err != nil || token == "" {
		t.Fatalf("sign-in = %q, %v", token, err)
	}
	u, err := o.Local.Store.GetUserByUsername(ctx, "ana@acme.com")
	if err != nil || u.Source != store.SourceOIDC || u.ExternalSubject != p.srv.URL+"#u-123" || u.Role != store.RoleUser ||
		len(u.Namespaces) != 1 || u.Namespaces[0] != "payments" || u.MustChangePassword {
		t.Fatalf("account = %+v, %v", u, err)
	}

	// A local password login is refused for the SSO account.
	if _, _, err := o.Local.Login(ctx, "ana@acme.com", "", "10.0.0.1", "t", "r"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("password login of an SSO account = %v", err)
	}

	// A rule for any authenticated user applies at once to existing accounts.
	if _, err := o.Local.SaveAccessRule(ctx, admin, "", AccessRuleInput{SubjectType: store.SubjectAuthenticated, Role: store.RoleUser,
		Namespaces: []string{"orders"}}, "r"); err != nil {
		t.Fatal(err)
	}
	u, _ = o.Local.Store.GetUser(ctx, u.ID)
	if strings.Join(u.Namespaces, ",") != "orders,payments" {
		t.Fatalf("namespaces after the new rule = %v", u.Namespaces)
	}

	// Disabled by an administrator: refused although its rules still match,
	// and neither a rule change nor a new sign-in enables it again.
	if _, err := o.Local.UpdateUser(ctx, admin, u.ID, UserInput{Disabled: true}, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := signIn(t, o, p, claims, nil); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("disabled SSO account signed in: %v", err)
	}
	if _, err := o.Local.SaveAccessRule(ctx, admin, "", AccessRuleInput{SubjectType: store.SubjectUser, Subject: "ana@acme.com", Role: store.RoleUser,
		AllNamespaces: true}, "r"); err != nil {
		t.Fatal(err)
	}
	if u, _ = o.Local.Store.GetUser(ctx, u.ID); !u.Disabled {
		t.Fatal("a rule change enabled the disabled account")
	}
	if _, err := o.Local.UpdateUser(ctx, admin, u.ID, UserInput{Disabled: false}, "r"); err != nil {
		t.Fatal(err)
	}
	if token, err := signIn(t, o, p, claims, nil); err != nil || token == "" {
		t.Fatalf("enabled again: %q %v", token, err)
	}
}

func TestOIDCSignInRefusals(t *testing.T) {
	o, p := newOIDC(t)
	ctx := context.Background()
	claims := map[string]any{"sub": "u-1", "email": "bob@acme.com", "email_verified": true, "groups": []string{"acme:dev"}}

	if _, err := signIn(t, o, p, claims, nil); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("without rules = %v", err)
	}
	if _, err := o.Local.Store.GetUserByUsername(ctx, "bob@acme.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an account was created without access")
	}

	admin := Identity{ID: "admin", Username: "admin"}
	if _, err := o.Local.SaveAccessRule(ctx, admin, "", AccessRuleInput{SubjectType: store.SubjectUser, Subject: "BOB@acme.com", Role: store.RoleAdmin}, "r"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*http.Request){
		"state from another browser": func(r *http.Request) { r.Header.Del("Cookie"); r.AddCookie(&http.Cookie{Name: oidcCookie, Value: "x"}) },
		"no state cookie":            func(r *http.Request) { r.Header.Del("Cookie") },
		"provider error":             func(r *http.Request) { r.URL.RawQuery += "&error=access_denied" },
		"forged code":                func(r *http.Request) { q := r.URL.Query(); q.Set("code", "forged"); r.URL.RawQuery = q.Encode() },
	}
	for name, tamper := range cases {
		if _, err := signIn(t, o, p, claims, tamper); !errors.Is(err, ErrSSOFailed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	unverified := map[string]any{"sub": "u-1", "email": "bob@acme.com", "email_verified": false}
	if _, err := signIn(t, o, p, unverified, nil); !errors.Is(err, ErrSSOFailed) {
		t.Errorf("unverified e-mail: err = %v", err)
	}
	if token, err := signIn(t, o, p, claims, nil); err != nil || token == "" {
		t.Fatalf("user rule: %v", err)
	}
	if u, _ := o.Local.Store.GetUserByUsername(ctx, "bob@acme.com"); u.Role != store.RoleAdmin {
		t.Errorf("role = %q", u.Role)
	}

	// A local account keeps its username: an SSO user with the same name is refused.
	if _, err := o.Local.SaveAccessRule(ctx, admin, "", AccessRuleInput{SubjectType: store.SubjectAuthenticated, Role: store.RoleUser, AllNamespaces: true}, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Local.CreateUser(ctx, admin, UserInput{Username: "carol", Role: store.RoleUser, AllNamespaces: true, Password: "a-long-password-1"}, "r"); err != nil {
		t.Fatal(err)
	}
	o.Config.UsernameClaim = "preferred_username"
	if _, err := signIn(t, o, p, map[string]any{"sub": "u-9", "preferred_username": "carol"}, nil); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("username of a local account: err = %v", err)
	}
}

func TestEvaluateRules(t *testing.T) {
	rules := []store.AccessRule{
		{SubjectType: store.SubjectGroup, Subject: "acme:ops", Role: store.RoleUser, Namespaces: []string{"b", "a"}},
		{SubjectType: store.SubjectGroup, Subject: "acme:platform", Role: store.RoleAdmin},
		{SubjectType: store.SubjectUser, Subject: "dana@acme.com", Role: store.RoleUser, AllowNetcheckNamespace: true, Namespaces: []string{"c"}},
	}
	if _, ok := EvaluateRules(rules, "eve@acme.com", []string{"acme:dev"}); ok {
		t.Error("no rule should match")
	}
	g, ok := EvaluateRules(rules, "DANA@acme.com", []string{"ACME:OPS"})
	if !ok || g.Role != store.RoleUser || strings.Join(g.Namespaces, ",") != "a,b,c" || !g.AllowNetcheckNamespace {
		t.Errorf("union = %+v %v", g, ok)
	}
	if g, _ := EvaluateRules(rules, "x", []string{"acme:platform"}); g.Role != store.RoleAdmin {
		t.Errorf("admin group = %+v", g)
	}
}
