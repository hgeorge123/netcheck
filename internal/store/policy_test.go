package store

import (
	"context"
	"errors"
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

func TestProxiesRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.GetProxies(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty database: %v", err)
	}
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ev := AuditEvent{ActorID: "u1", Action: "proxies.update", Outcome: "success"}
	if err := s.SaveProxies(ctx, StoredProxies{ProxiesJSON: `[{"name":"corp"}]`, UpdatedAt: now, UpdatedBy: "admin"}, ev); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetProxies(ctx)
	if err != nil || p.ProxiesJSON != `[{"name":"corp"}]` || p.UpdatedBy != "admin" || !p.UpdatedAt.Equal(now) {
		t.Fatalf("got %+v %v", p, err)
	}
}
