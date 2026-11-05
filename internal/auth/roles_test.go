package auth

import (
	"context"
	"slices"
	"testing"

	"github.com/hgeorge123/netcheck/internal/store"
)

func testRoles() *Roles {
	return &Roles{byID: map[string]store.Role{
		"ping-only": {ID: "ping-only", Name: "Ping only", Permissions: []string{CheckPermission("ping")}},
		"auditor":   {ID: "auditor", Name: "Auditor", Permissions: []string{CheckPermission("tcp"), PermRunsAll}},
	}}
}

// A role given for one namespace never applies to another (ADR 0005 §5):
// "ping-only in orders" plus "user in payments" must not allow TCP in orders.
func TestGrantsAreEvaluatedPerNamespace(t *testing.T) {
	ctx := context.Background()
	a := &Authorizer{Source: &mutableNS{list: []string{"orders", "payments", "billing"}}, Roles: testRoles()}
	id := Identity{ID: "u1", Role: RoleUser, Grants: []Grant{
		{Role: "ping-only", Namespaces: []string{"orders"}},
		{Role: RoleUser, Namespaces: []string{"payments"}},
	}}
	orders, ok, _ := a.Grant(ctx, id, "orders")
	if !ok || !slices.Equal(orders.Checks, []string{"ping"}) || orders.FirewallMode {
		t.Errorf("orders = %+v %v, want ping only", orders, ok)
	}
	payments, ok, _ := a.Grant(ctx, id, "payments")
	if !ok || len(payments.Checks) != len(CheckMethods) || !payments.FirewallMode {
		t.Errorf("payments = %+v %v, want every check", payments, ok)
	}
	if _, ok, _ := a.Grant(ctx, id, "billing"); ok {
		t.Error("billing granted without any grant reaching it")
	}
	// Grants reaching the same namespace add up.
	both := Identity{ID: "u2", Role: RoleUser, Grants: []Grant{
		{Role: "ping-only", Namespaces: []string{"orders"}},
		{Role: "auditor", Namespaces: []string{"orders"}},
	}}
	if g, _, _ := a.Grant(ctx, both, "orders"); !slices.Equal(g.Checks, []string{"tcp", "ping"}) {
		t.Errorf("union in orders = %v", g.Checks)
	}
}

func TestCustomRolePermissions(t *testing.T) {
	ctx := context.Background()
	roles := testRoles()
	a := &Authorizer{Source: &mutableNS{list: []string{"orders", "payments"}}, Roles: roles}
	auditor := Identity{ID: "u3", Role: "auditor", Namespaces: []string{"orders"}}
	if a.Has(auditor, PermTokensCreate) || a.Has(auditor, PermProxiesPersonal) || !a.Has(auditor, PermRunsAll) {
		t.Errorf("auditor permissions = %v", a.Permissions(auditor))
	}
	// runs.all: every test of its namespaces, not of the others.
	all, ns, own, err := a.RunScope(ctx, auditor)
	if err != nil || all || own != "" || !slices.Equal(ns, []string{"orders"}) {
		t.Errorf("auditor scope = %v %v %q %v", all, ns, own, err)
	}
	if ok, _ := a.CanViewRun(ctx, auditor, "someone", "orders"); !ok {
		t.Error("auditor cannot read a test of orders")
	}
	if ok, _ := a.CanViewRun(ctx, auditor, "someone", "payments"); ok {
		t.Error("auditor reads a test of a namespace it cannot use")
	}
	// The built-in roles keep their behaviour, and an unknown role grants nothing.
	user := Identity{ID: "u4", Role: RoleUser, AllNamespaces: true}
	if !a.Has(user, PermTokensCreate) || a.Has(user, PermRunsAll) {
		t.Errorf("user permissions = %v", a.Permissions(user))
	}
	if g, ok, _ := a.Grant(ctx, Identity{ID: "u5", Role: "deleted-role", AllNamespaces: true}, "orders"); !ok || len(g.Checks) != 0 {
		t.Errorf("unknown role = %+v %v, want no checks", g, ok)
	}
	if !roles.Exists("auditor") || roles.Exists("deleted-role") || !roles.Exists(RoleAdmin) {
		t.Error("Exists")
	}
}

func TestEvaluateGrantsOnePerRule(t *testing.T) {
	rules := []store.AccessRule{
		{SubjectType: store.SubjectGroup, Subject: "payments-team", Role: RoleUser, Namespaces: []string{"payments"}},
		{SubjectType: store.SubjectGroup, Subject: "ops", Role: "ping-only", AllNamespaces: true},
		{SubjectType: store.SubjectGroup, Subject: "ops-copy", Role: "ping-only", AllNamespaces: true},
		{SubjectType: store.SubjectGroup, Subject: "other", Role: RoleAdmin, AllNamespaces: true},
	}
	g := EvaluateGrants(rules, "ana", []string{"Payments-Team", "ops", "ops-copy"})
	if len(g) != 3 || g[0].Role != RoleUser || g[1].Source != "group:ops" || g[2].Source != "group:ops-copy" || !g[1].AllNamespaces {
		t.Errorf("grants = %+v, want user in payments and ping-only everywhere from each group", g)
	}
	if len(EvaluateGrants(rules, "ana", nil)) != 0 {
		t.Error("grants without matching rules")
	}
}
