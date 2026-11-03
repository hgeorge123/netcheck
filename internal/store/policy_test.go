package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDestinationPolicyRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.GetDestinationPolicy(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty database: %v", err)
	}
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	for i, body := range []string{`{"allowCidrs":["0.0.0.0/0"]}`, `{"allowCidrs":["10.0.0.0/8"]}`} {
		ev := AuditEvent{ActorID: "u1", Action: "policy.update", Outcome: "success"}
		if err := s.SaveDestinationPolicy(ctx, StoredPolicy{PolicyJSON: body, UpdatedAt: now.Add(time.Duration(i) * time.Hour), UpdatedBy: "admin"}, ev); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.GetDestinationPolicy(ctx)
	if err != nil || p.PolicyJSON != `{"allowCidrs":["10.0.0.0/8"]}` || p.UpdatedBy != "admin" || !p.UpdatedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("got %+v %v", p, err)
	}
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'policy.update'`).Scan(&n)
	if n != 2 {
		t.Errorf("audit events = %d, want 2", n)
	}
}

func TestTrustedCAsRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.GetTrustedCAs(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty database: %v", err)
	}
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for i, body := range []string{`[]`, `["-----BEGIN CERTIFICATE-----"]`} {
		ev := AuditEvent{ActorID: "u1", Action: "trusted_cas.update", Outcome: "success"}
		if err := s.SaveTrustedCAs(ctx, StoredTrustedCAs{CertificatesJSON: body, UpdatedAt: now.Add(time.Duration(i) * time.Hour), UpdatedBy: "admin"}, ev); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.GetTrustedCAs(ctx)
	if err != nil || c.CertificatesJSON != `["-----BEGIN CERTIFICATE-----"]` || c.UpdatedBy != "admin" || !c.UpdatedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("got %+v %v", c, err)
	}
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'trusted_cas.update'`).Scan(&n)
	if n != 2 {
		t.Errorf("audit events = %d, want 2", n)
	}
}

func TestProxyRecords(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ev := AuditEvent{ActorID: "u1", Action: "proxies.create", Outcome: "success"}
	ann := User{ID: "u-ann", Username: "ann", Role: RoleUser, PasswordHash: "x", CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
	if err := s.CreateUser(ctx, ann, ev); err != nil {
		t.Fatal(err)
	}
	rec := func(id, owner, name string) ProxyRecord {
		return ProxyRecord{ID: id, OwnerID: owner, Name: name, Host: "10.0.0.9", Port: 3128, CAsJSON: "[]", CreatedAt: now, UpdatedAt: now, UpdatedBy: "x"}
	}
	shared := rec("p1", "", "corp")
	shared.Shared = true
	for _, p := range []ProxyRecord{shared, rec("p2", "u-ann", "corp"), rec("p3", "u-ann", "home")} {
		if err := s.CreateProxy(ctx, p, ev); err != nil {
			t.Fatal(err)
		}
	}
	// Names are unique per owner: the same name may exist once shared and once personal.
	if err := s.CreateProxy(ctx, rec("p4", "u-ann", "home"), ev); !errors.Is(err, ErrProxyExists) {
		t.Errorf("duplicate personal name: %v", err)
	}
	if err := s.CreateProxy(ctx, rec("p5", "", "corp"), ev); !errors.Is(err, ErrProxyExists) {
		t.Errorf("duplicate shared name: %v", err)
	}
	list, err := s.ListProxies(ctx)
	if err != nil || len(list) != 3 || list[0].ID != "p1" || !list[0].Shared || list[0].OwnerID != "" || list[1].OwnerID != "u-ann" {
		t.Fatalf("list = %+v %v", list, err)
	}
	if n, _ := s.CountProxies(ctx, "u-ann"); n != 2 {
		t.Errorf("ann's count = %d", n)
	}
	// Nobody changes or deletes another owner's proxy.
	stolen := rec("p2", "u-bob", "corp")
	if err := s.UpdateProxy(ctx, stolen, ev); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of another owner's proxy: %v", err)
	}
	if err := s.DeleteProxy(ctx, "p1", "u-ann", ev); !errors.Is(err, ErrNotFound) {
		t.Errorf("user deleting a shared proxy: %v", err)
	}
	upd := rec("p2", "u-ann", "corp-2")
	upd.Port = 8080
	if err := s.UpdateProxy(ctx, upd, ev); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProxy(ctx, "p3", "u-ann", ev); err != nil {
		t.Fatal(err)
	}
	// Personal proxies go with their owner.
	if err := s.DeleteUser(ctx, "u-ann", ev); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListProxies(ctx); len(list) != 1 || list[0].ID != "p1" {
		t.Errorf("after deleting ann: %+v", list)
	}
	// Seeding happens once.
	if ok, err := s.SeedProxies(ctx, []ProxyRecord{rec("p9", "", "seeded")}, now, ev); err != nil || !ok {
		t.Fatalf("first seed: %v %v", ok, err)
	}
	if ok, err := s.SeedProxies(ctx, []ProxyRecord{rec("p10", "", "again")}, now, ev); err != nil || ok {
		t.Fatalf("second seed: %v %v", ok, err)
	}
}

func TestProxyRowsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	ctx := context.Background()
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	// Go back to the single-row list of version 11 and migrate again.
	for _, q := range []string{
		`DROP TABLE http_proxies`, `DROP TABLE proxy_seed`, `DELETE FROM schema_migrations WHERE version = 12`,
		`CREATE TABLE proxies (id INTEGER PRIMARY KEY CHECK (id = 1), proxies_json TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL)`,
		`INSERT INTO proxies VALUES (1, '[{"name":"corp","host":"proxy.example.com","port":3128},{"name":"dmz","host":"10.0.0.9","port":8080}]', '2026-11-03T10:00:00.000000000Z', 'admin')`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()
	s, err = Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, err := s.ListProxies(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "corp" || list[0].Host != "proxy.example.com" || list[0].Port != 3128 ||
		!list[0].Shared || list[0].OwnerID != "" || list[1].Port != 8080 || len(list[0].ID) != 25 {
		t.Fatalf("migrated = %+v %v", list, err)
	}
	if ok, _ := s.SeedProxies(ctx, nil, time.Now(), AuditEvent{Action: "x", Outcome: "y"}); ok {
		t.Error("a database that had proxies must count as seeded")
	}
}
