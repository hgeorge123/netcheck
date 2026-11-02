package store

import (
	"context"
	"testing"
	"time"
)

func mkUser(id, username, role string) User {
	now := time.Now().UTC()
	return User{ID: id, Username: username, DisplayName: username, Role: role, PasswordHash: "h", MustChangePassword: true,
		CreatedAt: now, UpdatedAt: now, PasswordChangedAt: now}
}

func TestUserCRUDAndCaseInsensitiveUsername(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser("u1", "Alice", RoleUser)
	u.Namespaces = []string{"payments", "orders", "payments"}
	if err := s.CreateUser(ctx, u, AuditEvent{Action: "user.create", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, mkUser("u2", "alice", RoleUser), AuditEvent{Action: "user.create", Outcome: "ok"}); err != ErrConflict {
		t.Fatalf("duplicate username (case-insensitive) err = %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "ALICE")
	if err != nil || got.ID != "u1" || len(got.Namespaces) != 2 || got.Namespaces[0] != "orders" || !got.MustChangePassword {
		t.Fatalf("got = %+v %v", got, err)
	}
	got.Namespaces, got.AllNamespaces, got.DisplayName = nil, true, "Alice A."
	if err := s.UpdateUser(ctx, got, time.Now(), AuditEvent{Action: "user.update", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, "u1")
	if !got.AllNamespaces || len(got.Namespaces) != 0 || got.DisplayName != "Alice A." {
		t.Errorf("update not applied: %+v", got)
	}
	if err := s.DeleteUser(ctx, "u1", AuditEvent{Action: "user.delete", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, "u1"); err != ErrNotFound {
		t.Errorf("deleted user still present: %v", err)
	}
}

func TestLastAdminIsProtected(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ev := AuditEvent{Action: "x", Outcome: "ok"}
	admin := mkUser("a1", "admin", RoleAdmin)
	if err := s.CreateUser(ctx, admin, ev); err != nil {
		t.Fatal(err)
	}
	demoted := admin
	demoted.Role = RoleUser
	if err := s.UpdateUser(ctx, demoted, time.Now(), ev); err != ErrLastAdmin {
		t.Errorf("demoting last admin err = %v", err)
	}
	disabled := admin
	disabled.Disabled = true
	if err := s.UpdateUser(ctx, disabled, time.Now(), ev); err != ErrLastAdmin {
		t.Errorf("disabling last admin err = %v", err)
	}
	if err := s.DeleteUser(ctx, "a1", ev); err != ErrLastAdmin {
		t.Errorf("deleting last admin err = %v", err)
	}
	// With a second admin the first one can be demoted.
	if err := s.CreateUser(ctx, mkUser("a2", "admin2", RoleAdmin), ev); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, demoted, time.Now(), ev); err != nil {
		t.Errorf("demote with another admin: %v", err)
	}
	if n, _ := s.CountActiveAdmins(ctx); n != 1 {
		t.Errorf("active admins = %d", n)
	}
}

func TestSessionsLockoutAndPasswordChange(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ev := AuditEvent{Action: "x", Outcome: "ok"}
	if err := s.CreateUser(ctx, mkUser("u1", "bob", RoleUser), ev); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, h := range []string{"s1", "s2"} {
		if err := s.CreateSession(ctx, Session{TokenHash: h, UserID: "u1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}, ev); err != nil {
			t.Fatal(err)
		}
	}
	if sess, err := s.GetSession(ctx, "s1"); err != nil || sess.UserID != "u1" {
		t.Fatalf("session = %+v %v", sess, err)
	}
	// Self password change keeps the current session only.
	if err := s.SetPassword(ctx, "u1", "h2", false, now, "s1", ev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "s2"); err != ErrNotFound {
		t.Error("other sessions must be revoked on password change")
	}
	if _, err := s.GetSession(ctx, "s1"); err != nil {
		t.Error("current session must survive self password change")
	}

	lock := now.Add(15 * time.Minute)
	for i := 1; i <= 3; i++ {
		if _, err := s.RecordLoginFailure(ctx, "u1", 3, lock, ev); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := s.GetUser(ctx, "u1")
	if u.LockedUntil == nil || u.FailedAttempts != 0 {
		t.Fatalf("account not locked after 3 failures: %+v", u)
	}
	if err := s.Unlock(ctx, "u1", now, ev); err != nil {
		t.Fatal(err)
	}
	if u, _ = s.GetUser(ctx, "u1"); u.LockedUntil != nil {
		t.Error("unlock did not clear the lock")
	}

	// Disabling revokes every session.
	u.Disabled = true
	if err := s.UpdateUser(ctx, u, now, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "s1"); err != ErrNotFound {
		t.Error("sessions must be revoked when a user is disabled")
	}

	if err := s.CreateSession(ctx, Session{TokenHash: "old", UserID: "u1", CreatedAt: now, LastSeenAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour)}, ev); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PurgeSessions(ctx, now, time.Hour); err != nil || n != 1 {
		t.Errorf("purge idle sessions = %d %v", n, err)
	}
}

func TestListRunsAllNamespaces(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for i, ns := range []string{"a", "b", "c"} {
		r, e := mkRun("run0000000"+string(rune('1'+i)), ns, time.Now().Add(time.Duration(i)*time.Second))
		if err := s.CreateRun(ctx, r, e, AuditEvent{Action: "run.create", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if runs, _, _ := s.ListRuns(ctx, ListFilter{AllNamespaces: true}); len(runs) != 3 {
		t.Errorf("all namespaces = %d runs", len(runs))
	}
	if runs, _, _ := s.ListRuns(ctx, ListFilter{AllNamespaces: true, Namespace: "b"}); len(runs) != 1 {
		t.Errorf("namespace filter with all = %d", len(runs))
	}
}
