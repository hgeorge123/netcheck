package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC sign-in: authorization code flow with PKCE, state bound to the
// browser by a cookie and a nonce checked in the ID token. NetCheck keeps no
// provider token: the ID token only establishes who the user is, and the
// session that follows is a normal NetCheck session.

// ErrSSOFailed covers every failed or forged SSO response (details are logged).
var ErrSSOFailed = errors.New("single sign-on failed")

const (
	oidcCookie     = "netcheck_oidc"
	oidcCookiePath = "/api/v1/auth/oidc"
	oidcPendingTTL = 10 * time.Minute
	oidcMaxPending = 10000
)

// OIDCConfig is the identity provider configuration.
type OIDCConfig struct {
	// Issuer must match the "iss" of the ID tokens.
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is https://<netcheck>/api/v1/auth/oidc/callback.
	RedirectURL string
	// InternalURL, when set, is where NetCheck reaches the provider inside
	// the cluster (the bundled Dex): token and keys are fetched there while
	// browsers use Issuer. Empty: endpoints come from Issuer discovery.
	InternalURL   string
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
}

type pendingLogin struct {
	nonce, verifier string
	expires         time.Time
}

// OIDC signs users in with an OpenID Connect provider.
type OIDC struct {
	Config OIDCConfig
	Local  *LocalAuth
	// HTTPClient talks to the provider (timeouts set by the caller).
	HTTPClient *http.Client

	mu       sync.Mutex
	pending  map[string]pendingLogin
	endpoint oauth2.Endpoint
	verifier *oidc.IDTokenVerifier
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// setup resolves the provider endpoints once; a failed discovery is retried
// on the next sign-in, so NetCheck starts even if the provider is down.
func (o *OIDC) setup(ctx context.Context) (oauth2.Endpoint, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.verifier != nil {
		return o.endpoint, o.verifier, nil
	}
	// The key set outlives the request that created it.
	bg := oidc.ClientContext(context.Background(), o.HTTPClient)
	cfg := &oidc.Config{ClientID: o.Config.ClientID}
	if o.Config.InternalURL != "" {
		base := strings.TrimSuffix(o.Config.InternalURL, "/")
		o.endpoint = oauth2.Endpoint{AuthURL: strings.TrimSuffix(o.Config.Issuer, "/") + "/auth", TokenURL: base + "/token", AuthStyle: oauth2.AuthStyleInHeader}
		o.verifier = oidc.NewVerifier(o.Config.Issuer, oidc.NewRemoteKeySet(bg, base+"/keys"), cfg)
		return o.endpoint, o.verifier, nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.HTTPClient), o.Config.Issuer)
	if err != nil {
		return oauth2.Endpoint{}, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	o.endpoint = p.Endpoint()
	o.verifier = p.VerifierContext(bg, cfg)
	return o.endpoint, o.verifier, nil
}

func (o *OIDC) oauth(endpoint oauth2.Endpoint) *oauth2.Config {
	return &oauth2.Config{ClientID: o.Config.ClientID, ClientSecret: o.Config.ClientSecret, RedirectURL: o.Config.RedirectURL,
		Endpoint: endpoint, Scopes: o.Config.Scopes}
}

// Start redirects the browser to the provider.
func (o *OIDC) Start(w http.ResponseWriter, r *http.Request) error {
	endpoint, _, err := o.setup(r.Context())
	if err != nil {
		return err
	}
	state, nonce, verifier := randomString(), randomString(), oauth2.GenerateVerifier()
	now := time.Now()
	o.mu.Lock()
	if o.pending == nil {
		o.pending = map[string]pendingLogin{}
	}
	for k, p := range o.pending {
		if now.After(p.expires) {
			delete(o.pending, k)
		}
	}
	if len(o.pending) >= oidcMaxPending {
		o.mu.Unlock()
		return errors.New("too many sign-ins in progress")
	}
	o.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, expires: now.Add(oidcPendingTTL)}
	o.mu.Unlock()
	// Lax: the provider sends the browser back with a cross-site navigation.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: state, Path: oidcCookiePath, HttpOnly: true, Secure: o.Local.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(oidcPendingTTL.Seconds())})
	http.Redirect(w, r, o.oauth(endpoint).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
	return nil
}

// ClearCookie removes the sign-in state cookie.
func (o *OIDC) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: oidcCookiePath, HttpOnly: true, Secure: o.Local.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Callback completes the sign-in and returns the session token. Errors other
// than ErrNoAccess and ErrUsernameTaken are wrapped in ErrSSOFailed.
func (o *OIDC) Callback(r *http.Request, clientIP, userAgent, requestID string) (string, error) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	c, err := r.Cookie(oidcCookie)
	if q.Get("error") != "" {
		return "", fmt.Errorf("%w: provider error %q", ErrSSOFailed, q.Get("error"))
	}
	if err != nil || state == "" || c.Value != state {
		return "", fmt.Errorf("%w: state does not match this browser", ErrSSOFailed)
	}
	o.mu.Lock()
	p, ok := o.pending[state]
	delete(o.pending, state)
	o.mu.Unlock()
	if !ok || time.Now().After(p.expires) {
		return "", fmt.Errorf("%w: sign-in expired, start again", ErrSSOFailed)
	}
	endpoint, verifier, err := o.setup(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSSOFailed, err)
	}
	tok, err := o.oauth(endpoint).Exchange(oidc.ClientContext(ctx, o.HTTPClient), q.Get("code"), oauth2.VerifierOption(p.verifier))
	if err != nil {
		return "", fmt.Errorf("%w: code exchange: %v", ErrSSOFailed, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", fmt.Errorf("%w: no ID token in the response", ErrSSOFailed)
	}
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("%w: ID token: %v", ErrSSOFailed, err)
	}
	if idt.Nonce != p.nonce {
		return "", fmt.Errorf("%w: nonce mismatch", ErrSSOFailed)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", fmt.Errorf("%w: claims: %v", ErrSSOFailed, err)
	}
	profile, err := o.profile(idt.Issuer, idt.Subject, claims)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSSOFailed, err)
	}
	token, _, err := o.Local.SignInSSO(ctx, profile, clientIP, userAgent, requestID)
	if err != nil && !errors.Is(err, ErrNoAccess) && !errors.Is(err, ErrUsernameTaken) {
		return "", fmt.Errorf("%w: %v", ErrSSOFailed, err)
	}
	return token, err
}

// profile extracts the username, display name and groups from the claims.
func (o *OIDC) profile(issuer, subject string, claims map[string]any) (SSOProfile, error) {
	str := func(k string) string { s, _ := claims[k].(string); return strings.TrimSpace(s) }
	username := str(o.Config.UsernameClaim)
	if o.Config.UsernameClaim == "sub" {
		username = subject
	}
	if username == "" {
		return SSOProfile{}, fmt.Errorf("claim %q is missing", o.Config.UsernameClaim)
	}
	if o.Config.UsernameClaim == "email" {
		if v, ok := claims["email_verified"].(bool); ok && !v {
			return SSOProfile{}, errors.New("the e-mail address is not verified by the provider")
		}
	}
	if len(username) > 128 || strings.ContainsFunc(username, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return SSOProfile{}, fmt.Errorf("claim %q is not a valid username", o.Config.UsernameClaim)
	}
	display := str("name")
	if display == "" {
		display = str("preferred_username")
	}
	if len(display) > 128 {
		display = display[:128]
	}
	var groups []string
	switch v := claims[o.Config.GroupsClaim].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" && len(s) <= 256 {
				groups = append(groups, s)
			}
		}
	case string:
		if v != "" {
			groups = []string{v}
		}
	}
	if len(groups) > 500 {
		groups = groups[:500]
	}
	return SSOProfile{Subject: issuer + "#" + subject, Username: username, DisplayName: display, Groups: groups}, nil
}
