package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
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

// Grant is a role with the namespaces where it applies: one access rule, the
// account of a local user, or (EvaluateRules) the union of matching rules.
type Grant struct {
	Role                   string   `json:"role"`
	AllNamespaces          bool     `json:"allNamespaces"`
	AllowNetcheckNamespace bool     `json:"allowNetcheckNamespace"`
	Namespaces             []string `json:"namespaces"`
	// Source says where the grant comes from: "account" (the user itself) or
	// the access rule ("group:<name>", "user:<name>", "authenticated").
	Source string `json:"source"`
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

// EvaluateGrants returns one grant per access rule matching an SSO identity,
// so the permissions of each role stay within the namespaces of its rule
// (ADR 0005 §5). Identical grants are kept once.
func EvaluateGrants(rules []store.AccessRule, username string, groups []string) []Grant {
	out := []Grant{}
	for _, r := range rules {
		if _, ok := EvaluateRules([]store.AccessRule{r}, username, groups); !ok {
			continue
		}
		g := Grant{Role: r.Role, AllNamespaces: r.AllNamespaces, AllowNetcheckNamespace: r.AllowNetcheckNamespace, Namespaces: slices.Clone(r.Namespaces),
			Source: ruleSource(r)}
		if g.Namespaces == nil {
			g.Namespaces = []string{}
		}
		if !slices.ContainsFunc(out, func(x Grant) bool { return reflect.DeepEqual(x, g) }) {
			out = append(out, g)
		}
	}
	return out
}

// ruleSource names the subject of a rule for the effective permissions view.
func ruleSource(r store.AccessRule) string {
	if r.SubjectType == store.SubjectAuthenticated {
		return "authenticated"
	}
	return r.SubjectType + ":" + r.Subject
}

// IdentityFor returns the identity of an account as a request would see it,
// with its grants (for the effective permissions of a user).
func (l *LocalAuth) IdentityFor(ctx context.Context, u store.User) Identity {
	return l.withGrants(ctx, identityOf(u, ""), u)
}

// withGrants adds the grants of an identity: for SSO, one per matching access
// rule (local accounts keep their own role and namespaces); for everybody,
// one per local group they are a member of.
func (l *LocalAuth) withGrants(ctx context.Context, id Identity, u store.User) Identity {
	id = l.ssoGrants(ctx, id, u)
	if groups := l.Groups.Of(u.ID); len(groups) > 0 {
		grants := slices.Clone(id.EffectiveGrants())
		for _, g := range groups {
			grants = append(grants, groupGrant(g))
		}
		id.Grants = grants
	}
	return id
}

// ssoGrants sets the grants of an SSO identity from the current rules.
func (l *LocalAuth) ssoGrants(ctx context.Context, id Identity, u store.User) Identity {
	if sourceOf(u) != store.SourceOIDC {
		return id
	}
	rules := l.rules.Load()
	if rules == nil {
		list, err := l.Store.ListAccessRules(ctx)
		if err != nil {
			// Fail closed: the permissions stored at the last sign-in can be
			// broader than a custom role (they are a union of the rules).
			id.Grants = []Grant{{Role: "", Namespaces: []string{}, Source: "unavailable"}}
			return id
		}
		rules = &list
		l.rules.Store(rules)
	}
	if g := EvaluateGrants(*rules, u.Username, u.ExternalGroups); len(g) > 0 {
		id.Grants = g
	}
	return id
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
	l.rules.Store(&rules)
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
