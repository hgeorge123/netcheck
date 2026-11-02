package store

import (
	"context"
	"testing"
	"time"
)

func TestLanguageAndNetcheckNamespaceFlag(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser("u1", "ana", RoleUser)
	if err := s.CreateUser(ctx, u, AuditEvent{Action: "x", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, "u1")
	if got.Language != "en" || got.AllowNetcheckNamespace {
		t.Fatalf("defaults: language=%q own=%v", got.Language, got.AllowNetcheckNamespace)
	}
	if err := s.SetLanguage(ctx, "u1", "es", time.Now()); err != nil {
		t.Fatal(err)
	}
	got.AllowNetcheckNamespace = true
	if err := s.UpdateUser(ctx, got, time.Now(), AuditEvent{Action: "x", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, "u1")
	if got.Language != "es" || !got.AllowNetcheckNamespace {
		t.Fatalf("after update: %+v", got)
	}
}

func TestActiveSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ev := AuditEvent{Action: "x", Outcome: "ok"}
	s.CreateUser(ctx, mkUser("u1", "ana", RoleUser), ev)
	now := time.Now().UTC()
	s.CreateSession(ctx, Session{ID: "s-active", TokenHash: "h1", UserID: "u1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
		ClientIP: "10.0.0.7", UserAgent: "Mozilla/5.0"}, ev)
	s.CreateSession(ctx, Session{ID: "s-idle", TokenHash: "h2", UserID: "u1", CreatedAt: now, LastSeenAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour)}, ev)
	list, err := s.ListActiveSessions(ctx, now, time.Hour)
	if err != nil || len(list) != 1 || list[0].ID != "s-active" || list[0].Username != "ana" || list[0].ClientIP != "10.0.0.7" {
		t.Fatalf("active = %+v %v", list, err)
	}
	if err := s.DeleteSessionByID(ctx, "s-active", ev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1"); err != ErrNotFound {
		t.Error("revoked session still valid")
	}
	if err := s.DeleteSessionByID(ctx, "", ev); err != ErrNotFound {
		t.Error("empty id must not match legacy sessions")
	}
}

func TestVersionHistory(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	v1 := AppVersion{Version: "0.1.0", Commit: "aaa", Image: "repo@sha256:1"}
	s.RecordVersion(ctx, v1, t0)
	s.RecordVersion(ctx, v1, t0.Add(time.Hour)) // restart, same build
	v2 := AppVersion{Version: "0.2.0", Commit: "bbb", Image: "repo@sha256:2"}
	s.RecordVersion(ctx, v2, t0.Add(48*time.Hour))
	list, err := s.ListVersions(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("versions = %+v %v", list, err)
	}
	if list[0].Version != "0.2.0" || list[1].Starts != 2 || !list[1].LastStartedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("history = %+v", list)
	}
}

func TestStats(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now().UTC()
	for i, ns := range []string{"a", "a", "b"} {
		r, e := mkRun("runstat000"+string(rune('1'+i)), ns, now.Add(-time.Duration(i)*time.Minute))
		s.CreateRun(ctx, r, e, AuditEvent{Action: "run.create", Outcome: "ok"})
	}
	st, err := s.Stats(ctx, ListFilter{AllowedNamespaces: []string{"a"}}, now.Add(-time.Hour))
	if err != nil || st.Total != 2 || st.ByStatus["queued"] != 2 || st.ByMethodStatus["tcp"]["queued"] != 2 {
		t.Fatalf("stats = %+v %v", st, err)
	}
	all, _ := s.Stats(ctx, ListFilter{AllNamespaces: true}, now.Add(-time.Hour))
	if all.Total != 3 {
		t.Errorf("all = %+v", all)
	}
}
