package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/hgeorge123/netcheck/internal/store"
)

// ErrNoAccess is returned when no access rule matches an SSO identity.
var ErrNoAccess = errors.New("no access rule matches this account")

// ErrUsernameTaken is returned when an SSO username belongs to a local account.
var ErrUsernameTaken = errors.New("the username belongs to a local account")

// SSOProfile is what the identity provider asserted about the user.
type SSOProfile struct {
	// Subject is "<issuer>#<sub>": stable for the life of the account.
	Subject     string
	Username    string
	DisplayName string
	Groups      []string
}

// Grant is the union of the permissions of every matching access rule.
type Grant struct {
	Role                   string
	AllNamespaces          bool
	AllowNetcheckNamespace bool
	Namespaces             []string
}

// EvaluateRules returns the permissions an SSO identity gets and whether any
// rule matched. Group and user subjects are compared case-insensitively.
func EvaluateRules(rules []store.AccessRule, username string, groups []string) (Grant, bool) {
	g := Grant{Role: store.RoleUser, Namespaces: []string{}}
	matched := false
	for _, r := range rules {
		match := false
		switch r.SubjectType {
		case store.SubjectAuthenticated:
			match = true
		case store.SubjectUser:
			match = strings.EqualFold(r.Subject, username)
		case store.SubjectGroup:
			match = slices.ContainsFunc(groups, func(x string) bool { return strings.EqualFold(x, r.Subject) })
		}
		if !match {
			continue
		}
		matched = true
		if r.Role == store.RoleAdmin {
			g.Role = store.RoleAdmin
		}
		g.AllNamespaces = g.AllNamespaces || r.AllNamespaces
		g.AllowNetcheckNamespace = g.AllowNetcheckNamespace || r.AllowNetcheckNamespace
		for _, ns := range r.Namespaces {
			if !slices.Contains(g.Namespaces, ns) {
				g.Namespaces = append(g.Namespaces, ns)
			}
		}
	}
	slices.Sort(g.Namespaces)
	if g.AllNamespaces {
		g.Namespaces = []string{}
	}
	return g, matched
}

func apply(u *store.User, g Grant) {
	u.Role, u.AllNamespaces, u.AllowNetcheckNamespace, u.Namespaces = g.Role, g.AllNamespaces, g.AllowNetcheckNamespace, g.Namespaces
}

// SignInSSO maps an identity asserted by the provider to a NetCheck account
// and opens a session. The account is created at the first sign-in; its
// permissions are recomputed from the access rules every time.
func (l *LocalAuth) SignInSSO(ctx context.Context, p SSOProfile, clientIP, userAgent, requestID string) (string, Identity, error) {
	p.Username = strings.ToLower(strings.TrimSpace(p.Username))
	audit := map[string]any{"username": p.Username, "groups": p.Groups, "clientIp": clientIP, "method": "oidc"}
	fail := func(actor, reason string, err error) (string, Identity, error) {
		audit["reason"] = reason
		_ = l.Store.InsertAudit(ctx, store.AuditEvent{ActorID: actor, Action: "auth.login", Outcome: "failed", RequestID: requestID, DetailsJSON: details(audit)})
		return "", Identity{}, err
	}
	rules, err := l.Store.ListAccessRules(ctx)
	if err != nil {
		return "", Identity{}, err
	}
	grant, ok := EvaluateRules(rules, p.Username, p.Groups)

	u, err := l.Store.GetUserByExternalSubject(ctx, p.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !ok {
			return fail("", "no access rule", ErrNoAccess)
		}
		if _, err := l.Store.GetUserByUsername(ctx, p.Username); err == nil {
			return fail("", "username used by another account", ErrUsernameTaken)
		}
		now := l.now()
		u = store.User{ID: newUserID(), Username: p.Username, DisplayName: p.DisplayName, Source: store.SourceOIDC,
			ExternalSubject: p.Subject, ExternalGroups: p.Groups, CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
		apply(&u, grant)
		err = l.Store.CreateUser(ctx, u, store.AuditEvent{ActorID: u.ID, Action: "user.create", Outcome: "success", RequestID: requestID,
			DetailsJSON: details(map[string]any{"userId": u.ID, "username": u.Username, "source": store.SourceOIDC, "role": u.Role})})
		if errors.Is(err, store.ErrConflict) {
			return fail("", "username used by another account", ErrUsernameTaken)
		}
		if err != nil {
			return "", Identity{}, err
		}
	case err != nil:
		return "", Identity{}, err
	default:
		if u.Disabled {
			return fail(u.ID, "disabled", ErrNoAccess)
		}
		u.DisplayName, u.ExternalGroups = p.DisplayName, p.Groups
		apply(&u, grant)
		if err := l.Store.SyncSSOUser(ctx, u, ok, l.now()); err != nil {
			return "", Identity{}, err
		}
		if !ok {
			return fail(u.ID, "no access rule", ErrNoAccess)
		}
	}
	return l.newSession(ctx, u, clientIP, userAgent, requestID, audit)
}

// ResyncSSO recomputes the permissions of every SSO account from its last
// groups, so a rule change applies at once. Accounts left without a rule
// lose their sessions.
func (l *LocalAuth) ResyncSSO(ctx context.Context) error {
	rules, err := l.Store.ListAccessRules(ctx)
	if err != nil {
		return err
	}
	users, err := l.Store.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Source != store.SourceOIDC {
			continue
		}
		g, ok := EvaluateRules(rules, u.Username, u.ExternalGroups)
		apply(&u, g)
		if err := l.Store.SyncSSOUser(ctx, u, ok, l.now()); err != nil {
			return err
		}
	}
	return nil
}

// AccessRuleInput is the admin payload of an access rule.
type AccessRuleInput struct {
	SubjectType            string   `json:"subjectType"`
	Subject                string   `json:"subject"`
	Role                   string   `json:"role"`
	AllNamespaces          bool     `json:"allNamespaces"`
	AllowNetcheckNamespace bool     `json:"allowNetcheckNamespace"`
	Namespaces             []string `json:"namespaces"`
}

func (l *LocalAuth) validateRule(ctx context.Context, in *AccessRuleInput) error {
	in.Subject = strings.TrimSpace(in.Subject)
	switch in.SubjectType {
	case store.SubjectAuthenticated:
		in.Subject = ""
	case store.SubjectUser:
		in.Subject = strings.ToLower(in.Subject)
		fallthrough
	case store.SubjectGroup:
		if in.Subject == "" || len(in.Subject) > 256 || strings.ContainsFunc(in.Subject, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return InputError{"subject", "subject_invalid", "enter the group or username (1-256 printable characters)"}
		}
	default:
		return InputError{"subjectType", "subject_type_invalid", "the rule must apply to a group, a user or any authenticated user"}
	}
	p := UserInput{Role: in.Role, AllNamespaces: in.AllNamespaces, Namespaces: in.Namespaces, AllowNetcheckNamespace: in.AllowNetcheckNamespace}
	if err := l.validateProfile(ctx, &p); err != nil {
		return err
	}
	in.Namespaces = p.Namespaces
	return nil
}

func newRuleID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "r" + hex.EncodeToString(b)
}

// SaveAccessRule creates (id "") or replaces a rule and applies it at once.
func (l *LocalAuth) SaveAccessRule(ctx context.Context, actor Identity, id string, in AccessRuleInput, requestID string) (store.AccessRule, error) {
	if err := l.validateRule(ctx, &in); err != nil {
		return store.AccessRule{}, err
	}
	now := l.now()
	r := store.AccessRule{ID: id, SubjectType: in.SubjectType, Subject: in.Subject, Role: in.Role, AllNamespaces: in.AllNamespaces,
		AllowNetcheckNamespace: in.AllowNetcheckNamespace, Namespaces: in.Namespaces, CreatedAt: now, UpdatedAt: now, UpdatedBy: actor.Username}
	action := "access_rule.update"
	if id == "" {
		r.ID, action = newRuleID(), "access_rule.create"
	} else {
		cur, err := l.Store.GetAccessRule(ctx, id)
		if err != nil {
			return store.AccessRule{}, err
		}
		r.CreatedAt = cur.CreatedAt
	}
	err := l.Store.SaveAccessRule(ctx, r, store.AuditEvent{ActorID: actor.ID, Action: action, Outcome: "success", RequestID: requestID,
		DetailsJSON: details(map[string]any{"ruleId": r.ID, "subjectType": r.SubjectType, "subject": r.Subject, "role": r.Role,
			"allNamespaces": r.AllNamespaces, "namespaces": r.Namespaces})})
	if errors.Is(err, store.ErrConflict) {
		return store.AccessRule{}, InputError{"subject", "rule_exists", "there is already a rule for that subject"}
	}
	if err != nil {
		return store.AccessRule{}, err
	}
	return r, l.ResyncSSO(ctx)
}

// DeleteAccessRule removes a rule and applies the change at once.
func (l *LocalAuth) DeleteAccessRule(ctx context.Context, actor Identity, id, requestID string) error {
	r, err := l.Store.GetAccessRule(ctx, id)
	if err != nil {
		return err
	}
	if err := l.Store.DeleteAccessRule(ctx, id, store.AuditEvent{ActorID: actor.ID, Action: "access_rule.delete", Outcome: "success",
		RequestID: requestID, DetailsJSON: details(map[string]any{"ruleId": r.ID, "subjectType": r.SubjectType, "subject": r.Subject})}); err != nil {
		return err
	}
	return l.ResyncSSO(ctx)
}
