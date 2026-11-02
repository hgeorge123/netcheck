package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/store"
)

// CookieName is the session cookie.
const CookieName = "netcheck_session"

var (
	// ErrInvalidCredentials is deliberately generic (no user enumeration).
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrRateLimited is returned when a client IP exceeds the login rate.
	ErrRateLimited = errors.New("too many login attempts")
	// ErrForbiddenSelf protects admins from locking themselves out.
	ErrForbiddenSelf = errors.New("operation not allowed on your own account")
)

// InputError is a user-correctable validation error. Code is stable and
// translated by the UI; Message is an English fallback.
type InputError struct {
	Field   string
	Code    string
	Message string
}

func (e InputError) Error() string { return e.Field + ": " + e.Message }

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// LocalAuth authenticates local accounts and administers users.
type LocalAuth struct {
	Store          *store.Store
	Namespaces     NamespaceSource
	SessionIdle    time.Duration
	SessionMax     time.Duration
	MaxFailures    int
	LockDuration   time.Duration
	CookieSecure   bool
	LoginLimiter   *RateLimiter
	TrustedProxies []netip.Prefix
	Now            func() time.Time

	dummyOnce sync.Once
	dummyHash string
}

func (l *LocalAuth) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newUserID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "u" + hex.EncodeToString(b)
}

func identityOf(u store.User, sessionHash string) Identity {
	ns := u.Namespaces
	if ns == nil {
		ns = []string{}
	}
	display := u.DisplayName
	if display == "" {
		display = u.Username
	}
	return Identity{ID: u.ID, Username: u.Username, Display: display, Role: u.Role, AllNamespaces: u.AllNamespaces,
		Namespaces: ns, MustChangePassword: u.MustChangePassword, Language: languageOrDefault(u.Language),
		AllowNetcheckNamespace: u.AllowNetcheckNamespace, SessionHash: sessionHash}
}

func newSessionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "s" + hex.EncodeToString(b)
}

// Languages supported by the UI. English is the default regardless of the
// browser; the user's choice is stored in the database.
var Languages = []string{"en", "es"}

func languageOrDefault(l string) string {
	if slices.Contains(Languages, l) {
		return l
	}
	return "en"
}

// SetLanguage stores the UI language of the caller.
func (l *LocalAuth) SetLanguage(ctx context.Context, id Identity, language string) error {
	if !slices.Contains(Languages, language) {
		return InputError{"language", "language_invalid", "supported languages: en, es"}
	}
	return l.Store.SetLanguage(ctx, id.ID, language, l.now())
}

// ActiveSessions lists sessions that are neither expired nor idle.
func (l *LocalAuth) ActiveSessions(ctx context.Context) ([]store.ActiveSession, error) {
	return l.Store.ListActiveSessions(ctx, l.now(), l.SessionIdle)
}

// RevokeSession signs a session out. Admins cannot revoke their own current
// session this way (use logout).
func (l *LocalAuth) RevokeSession(ctx context.Context, actor Identity, sessionID, requestID string) error {
	sess, err := l.Store.GetSession(ctx, actor.SessionHash)
	if err == nil && sess.ID == sessionID {
		return ErrForbiddenSelf
	}
	return l.Store.DeleteSessionByID(ctx, sessionID, store.AuditEvent{ActorID: actor.ID, Action: "session.revoke", Outcome: "success",
		RequestID: requestID, DetailsJSON: details(map[string]any{"sessionId": sessionID})})
}

func details(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Authenticate implements Authenticator from the session cookie.
func (l *LocalAuth) Authenticate(r *http.Request) (Identity, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return Identity{}, ErrUnauthenticated
	}
	h := hashToken(c.Value)
	ctx := r.Context()
	sess, err := l.Store.GetSession(ctx, h)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	now := l.now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > l.SessionIdle {
		_ = l.Store.DeleteSession(ctx, h)
		return Identity{}, ErrUnauthenticated
	}
	u, err := l.Store.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		return Identity{}, ErrUnauthenticated
	}
	// Throttle activity writes to once a minute.
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = l.Store.TouchSession(ctx, h, now)
	}
	return identityOf(u, h), nil
}

// Login verifies credentials and creates a session. It returns the raw
// session token for the cookie.
func (l *LocalAuth) Login(ctx context.Context, username, password, clientIP, userAgent, requestID string) (string, Identity, error) {
	if l.LoginLimiter != nil && !l.LoginLimiter.Allow(clientIP) {
		_ = l.Store.InsertAudit(ctx, store.AuditEvent{Action: "auth.login", Outcome: "rate_limited", RequestID: requestID,
			DetailsJSON: details(map[string]any{"clientIp": clientIP})})
		return "", Identity{}, ErrRateLimited
	}
	l.dummyOnce.Do(func() {
		l.dummyHash, _ = HashPassword(newToken())
	})
	username = strings.ToLower(strings.TrimSpace(username))
	u, err := l.Store.GetUserByUsername(ctx, username)
	if err != nil {
		// Pay the hashing cost anyway so response time does not reveal
		// whether the user exists.
		_, _ = VerifyPassword(password, l.dummyHash)
		_ = l.Store.InsertAudit(ctx, store.AuditEvent{Action: "auth.login", Outcome: "failed", RequestID: requestID,
			DetailsJSON: details(map[string]any{"username": username, "reason": "unknown user", "clientIp": clientIP})})
		return "", Identity{}, ErrInvalidCredentials
	}
	now := l.now()
	ok, _ := VerifyPassword(password, u.PasswordHash)
	locked := u.LockedUntil != nil && now.Before(*u.LockedUntil)
	if !ok || locked || u.Disabled {
		reason := "bad password"
		switch {
		case locked:
			reason = "locked"
		case u.Disabled:
			reason = "disabled"
		}
		ev := store.AuditEvent{ActorID: u.ID, Action: "auth.login", Outcome: "failed", RequestID: requestID,
			DetailsJSON: details(map[string]any{"username": u.Username, "reason": reason, "clientIp": clientIP})}
		if !ok && !locked {
			_, _ = l.Store.RecordLoginFailure(ctx, u.ID, l.MaxFailures, now.Add(l.LockDuration), ev)
		} else {
			_ = l.Store.InsertAudit(ctx, ev)
		}
		return "", Identity{}, ErrInvalidCredentials
	}
	token := newToken()
	h := hashToken(token)
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	err = l.Store.CreateSession(ctx, store.Session{ID: newSessionID(), TokenHash: h, UserID: u.ID, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(l.SessionMax), ClientIP: clientIP, UserAgent: userAgent},
		store.AuditEvent{ActorID: u.ID, Action: "auth.login", Outcome: "success", RequestID: requestID,
			DetailsJSON: details(map[string]any{"username": u.Username, "clientIp": clientIP})})
	if err != nil {
		return "", Identity{}, err
	}
	return token, identityOf(u, h), nil
}

// Logout deletes the current session.
func (l *LocalAuth) Logout(ctx context.Context, id Identity, requestID string) error {
	_ = l.Store.InsertAudit(ctx, store.AuditEvent{ActorID: id.ID, Action: "auth.logout", Outcome: "success", RequestID: requestID})
	return l.Store.DeleteSession(ctx, id.SessionHash)
}

// SetCookie writes the session cookie.
func (l *LocalAuth) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, Secure: l.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(l.SessionMax.Seconds())})
}

// ClearCookie expires the session cookie.
func (l *LocalAuth) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: l.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// ClientIP resolves the client address honouring trusted proxies.
func (l *LocalAuth) ClientIP(r *http.Request) string { return ClientIP(r, l.TrustedProxies) }

// ChangeOwnPassword verifies the current password and sets a new one. The
// caller's session is kept; every other session is revoked.
func (l *LocalAuth) ChangeOwnPassword(ctx context.Context, id Identity, current, next, requestID string) error {
	u, err := l.Store.GetUser(ctx, id.ID)
	if err != nil {
		return err
	}
	if ok, _ := VerifyPassword(current, u.PasswordHash); !ok {
		_ = l.Store.InsertAudit(ctx, store.AuditEvent{ActorID: u.ID, Action: "auth.password_change", Outcome: "failed", RequestID: requestID,
			DetailsJSON: details(map[string]any{"reason": "bad current password"})})
		return InputError{"currentPassword", "current_password_wrong", "the current password is not correct"}
	}
	if err := ValidatePassword(next, u.Username); err != nil {
		return weak("newPassword", err)
	}
	if current == next {
		return InputError{"newPassword", "password_unchanged", "the new password must be different from the current one"}
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	return l.Store.SetPassword(ctx, u.ID, hash, false, l.now(), id.SessionHash,
		store.AuditEvent{ActorID: u.ID, Action: "auth.password_change", Outcome: "success", RequestID: requestID})
}

// UserInput is the admin payload to create or update a user.
type UserInput struct {
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Role          string   `json:"role"`
	Password      string   `json:"password,omitempty"`
	AllNamespaces bool     `json:"allNamespaces"`
	Namespaces    []string `json:"namespaces"`
	Disabled      bool     `json:"disabled"`
	// AllowNetcheckNamespace exposes the NetCheck namespace to this user.
	AllowNetcheckNamespace bool `json:"allowNetcheckNamespace"`
}

func (l *LocalAuth) validateProfile(ctx context.Context, in *UserInput) error {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if len(in.DisplayName) > 128 {
		return InputError{"displayName", "display_name_too_long", "the display name cannot exceed 128 characters"}
	}
	for _, r := range in.DisplayName {
		if r < 0x20 || r == 0x7f {
			return InputError{"displayName", "display_name_invalid", "the display name contains characters that are not allowed"}
		}
	}
	if in.Role != store.RoleAdmin && in.Role != store.RoleUser {
		return InputError{"role", "role_invalid", "the role must be admin or user"}
	}
	if in.AllNamespaces {
		in.Namespaces = nil
		return nil
	}
	if in.Role == store.RoleUser && len(in.Namespaces) == 0 && !in.AllowNetcheckNamespace {
		return InputError{"namespaces", "namespaces_required", "select at least one namespace or all namespaces"}
	}
	avail, err := l.Namespaces.Available(ctx)
	if err != nil {
		return err
	}
	for _, ns := range in.Namespaces {
		if !slices.Contains(avail, ns) {
			return InputError{"namespaces", "namespace_unavailable", fmt.Sprintf("namespace %q is not available", ns)}
		}
	}
	return nil
}

// CreateUser creates a user with a temporary password that must be changed
// at the first login.
func (l *LocalAuth) CreateUser(ctx context.Context, actor Identity, in UserInput, requestID string) (store.User, error) {
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !usernamePattern.MatchString(in.Username) {
		return store.User{}, InputError{"username", "username_invalid", "3-64 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit"}
	}
	if err := l.validateProfile(ctx, &in); err != nil {
		return store.User{}, err
	}
	if err := ValidatePassword(in.Password, in.Username); err != nil {
		return store.User{}, weak("password", err)
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return store.User{}, err
	}
	now := l.now()
	u := store.User{ID: newUserID(), Username: in.Username, DisplayName: in.DisplayName, Role: in.Role, PasswordHash: hash,
		MustChangePassword: true, AllNamespaces: in.AllNamespaces, Namespaces: in.Namespaces, AllowNetcheckNamespace: in.AllowNetcheckNamespace, CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
	err = l.Store.CreateUser(ctx, u, store.AuditEvent{ActorID: actor.ID, Action: "user.create", Outcome: "success", RequestID: requestID,
		DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username, "role": u.Role, "allNamespaces": u.AllNamespaces, "namespaces": u.Namespaces})})
	if errors.Is(err, store.ErrConflict) {
		return store.User{}, InputError{"username", "username_taken", "a user with that name already exists"}
	}
	if err != nil {
		return store.User{}, err
	}
	return l.Store.GetUser(ctx, u.ID)
}

// UpdateUser changes profile, role, namespaces or the disabled flag.
func (l *LocalAuth) UpdateUser(ctx context.Context, actor Identity, userID string, in UserInput, requestID string) (store.User, error) {
	u, err := l.Store.GetUser(ctx, userID)
	if err != nil {
		return store.User{}, err
	}
	if userID == actor.ID && (in.Role != store.RoleAdmin || in.Disabled) {
		return store.User{}, ErrForbiddenSelf
	}
	if err := l.validateProfile(ctx, &in); err != nil {
		return store.User{}, err
	}
	u.DisplayName, u.Role, u.AllNamespaces, u.Namespaces, u.Disabled = in.DisplayName, in.Role, in.AllNamespaces, in.Namespaces, in.Disabled
	u.AllowNetcheckNamespace = in.AllowNetcheckNamespace
	err = l.Store.UpdateUser(ctx, u, l.now(), store.AuditEvent{ActorID: actor.ID, Action: "user.update", Outcome: "success", RequestID: requestID,
		DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username, "role": u.Role, "disabled": u.Disabled,
			"allNamespaces": u.AllNamespaces, "namespaces": u.Namespaces})})
	if err != nil {
		return store.User{}, err
	}
	return l.Store.GetUser(ctx, u.ID)
}

// ResetPassword sets a temporary password chosen by an admin. The user must
// change it at the next login and every session is revoked.
func (l *LocalAuth) ResetPassword(ctx context.Context, actor Identity, userID, password, requestID string) error {
	u, err := l.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := ValidatePassword(password, u.Username); err != nil {
		return weak("password", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return l.Store.SetPassword(ctx, u.ID, hash, true, l.now(), "",
		store.AuditEvent{ActorID: actor.ID, Action: "user.password_reset", Outcome: "success", RequestID: requestID,
			DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username})})
}

// Unlock clears a lockout.
func (l *LocalAuth) Unlock(ctx context.Context, actor Identity, userID, requestID string) error {
	return l.Store.Unlock(ctx, userID, l.now(), store.AuditEvent{ActorID: actor.ID, Action: "user.unlock", Outcome: "success",
		RequestID: requestID, DetailsJSON: details(map[string]any{"userId": userID})})
}

// DeleteUser removes a user. Admins cannot delete themselves.
func (l *LocalAuth) DeleteUser(ctx context.Context, actor Identity, userID, requestID string) error {
	if userID == actor.ID {
		return ErrForbiddenSelf
	}
	u, err := l.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	return l.Store.DeleteUser(ctx, userID, store.AuditEvent{ActorID: actor.ID, Action: "user.delete", Outcome: "success",
		RequestID: requestID, DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username})})
}

// RecoverBootstrapAdmin is the break-glass procedure for a lost admin
// password. It requires cluster access (Helm value + Secret) and resets the
// bootstrap account to the Secret password: admin role, enabled, unlocked,
// must change password, all sessions revoked. Audited.
func (l *LocalAuth) RecoverBootstrapAdmin(ctx context.Context, username, password string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if err := ValidatePassword(password, username); err != nil {
		return fmt.Errorf("bootstrap admin password: %w", err)
	}
	u, err := l.Store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_, err = l.EnsureBootstrapAdmin(ctx, username, password, true)
		return err
	}
	if err != nil {
		return err
	}
	now := l.now()
	u.Role, u.Disabled = store.RoleAdmin, false
	ev := store.AuditEvent{ActorID: "system:recovery", Action: "user.recovery", Outcome: "success",
		DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username})}
	if err := l.Store.UpdateUser(ctx, u, now, ev); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return l.Store.SetPassword(ctx, u.ID, hash, true, now, "", ev)
}

// EnsureBootstrapAdmin creates the initial admin when no admin exists.
// It never modifies existing accounts.
func (l *LocalAuth) EnsureBootstrapAdmin(ctx context.Context, username, password string, forceChange bool) (bool, error) {
	n, err := l.Store.CountActiveAdmins(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if !usernamePattern.MatchString(username) {
		return false, fmt.Errorf("bootstrap admin username %q is invalid", username)
	}
	if err := ValidatePassword(password, username); err != nil {
		return false, fmt.Errorf("bootstrap admin password: %w", err)
	}
	if _, err := l.Store.GetUserByUsername(ctx, username); err == nil {
		return false, fmt.Errorf("user %q exists but there is no active admin; fix it manually", username)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return false, err
	}
	now := l.now()
	u := store.User{ID: newUserID(), Username: username, DisplayName: "Administrator", Role: store.RoleAdmin, PasswordHash: hash,
		MustChangePassword: forceChange, AllNamespaces: true, CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
	return true, l.Store.CreateUser(ctx, u, store.AuditEvent{ActorID: "system:bootstrap", Action: "user.create", Outcome: "success",
		DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username, "role": u.Role, "bootstrap": true})})
}
