package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"), true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkRun(id, ns string, created time.Time) (Run, []Execution) {
	r := Run{ID: id, CreatedAt: created, ActorID: "u1", ActorDisplay: "User", Namespace: ns, ClusterID: "c1",
		Target: "10.0.0.1", Status: RunQueued, RequestJSON: "{}", SpecJSON: "{}"}
	execs := []Execution{
		{ID: id + "-1", Seq: 1, CheckID: "1-tcp", Method: "tcp", Status: RunQueued},
		{ID: id + "-2", Seq: 2, CheckID: "2-http", Method: "http", Status: RunQueued},
	}
	return r, execs
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		s, err := Open(ctx, path, false)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		v, err := s.SchemaVersion(ctx)
		if err != nil || v != 7 {
			t.Fatalf("schema version = %d, %v", v, err)
		}
		s.Close()
	}
}

func TestRunLifecyclePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "life.db")
	s, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	r, execs := mkRun("run00000001", "lab-a", now)
	if err := s.CreateRun(ctx, r, execs, AuditEvent{ActorID: "u1", Action: "run.create", Outcome: "accepted"}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRunning(ctx, r.ID, "netcheck-run00000001", `{"level":"x"}`, now); err != nil {
		t.Fatal(err)
	}
	dur := int64(12)
	err = s.CompleteRun(ctx, r.ID, Completion{
		Status: RunFailed, FailureCategory: "timeout", FinishedAt: now.Add(time.Second),
		Executions: []Execution{{CheckID: "1-tcp", Status: "timed_out", Category: "timeout", DurationMS: &dur, Stdout: "out", PodIP: "10.1.1.1"}},
		// The HTTP check is missing from the result: it must not stay "running".
		ExecutionFallbackStatus: "infra_error",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, gotExecs, err := s2.GetRun(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RunFailed || got.JobName != "netcheck-run00000001" || got.FinishedAt == nil || !got.CreatedAt.Equal(now) {
		t.Errorf("run = %+v", got)
	}
	if len(gotExecs) != 2 || gotExecs[0].Status != "timed_out" || *gotExecs[0].DurationMS != 12 || gotExecs[1].Status != "infra_error" {
		t.Errorf("execs = %+v", gotExecs)
	}
	// Terminal runs cannot be completed twice.
	if err := s2.CompleteRun(ctx, r.ID, Completion{Status: RunSucceeded, FinishedAt: now}); err != ErrNotFound {
		t.Errorf("second completion err = %v", err)
	}
}

func TestListRunsPaginationAndNamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		ns := "lab-a"
		if i%5 == 0 {
			ns = "secret-ns"
		}
		r, execs := mkRun(fmt.Sprintf("run%08d", i), ns, base.Add(time.Duration(i)*time.Minute))
		// Two runs share a timestamp to exercise the id tie-breaker.
		if i == 7 {
			r.CreatedAt = base.Add(6 * time.Minute)
		}
		if err := s.CreateRun(ctx, r, execs, AuditEvent{Action: "run.create", Outcome: "accepted"}); err != nil {
			t.Fatal(err)
		}
	}
	var all []Run
	cursor := ""
	for page := 0; page < 10; page++ {
		runs, next, err := s.ListRuns(ctx, ListFilter{AllowedNamespaces: []string{"lab-a"}, PageSize: 7, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, runs...)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(all) != 20 {
		t.Fatalf("got %d runs, want 20", len(all))
	}
	seen := map[string]bool{}
	for i, r := range all {
		if r.Namespace != "lab-a" {
			t.Fatalf("leaked run from namespace %s", r.Namespace)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate %s across pages", r.ID)
		}
		seen[r.ID] = true
		if i > 0 && all[i-1].CreatedAt.Before(r.CreatedAt) {
			t.Fatal("not ordered newest first")
		}
	}
	if runs, _, _ := s.ListRuns(ctx, ListFilter{}); len(runs) != 0 {
		t.Error("no allowed namespaces must return nothing")
	}
	// A filter for a namespace outside the allowed list returns nothing.
	if runs, _, _ := s.ListRuns(ctx, ListFilter{AllowedNamespaces: []string{"lab-a"}, Namespace: "secret-ns"}); len(runs) != 0 {
		t.Error("filter must not escape allowed namespaces")
	}
	if _, _, err := s.ListRuns(ctx, ListFilter{AllowedNamespaces: []string{"lab-a"}, Cursor: "!!"}); err != ErrInvalidCursor {
		t.Errorf("bad cursor err = %v", err)
	}
	if runs, _, _ := s.ListRuns(ctx, ListFilter{AllowedNamespaces: []string{"lab-a"}, Status: RunSucceeded}); len(runs) != 0 {
		t.Error("status filter not applied")
	}
}

func TestPurgeRetention(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now().UTC()
	old, oldExecs := mkRun("runold0001", "lab-a", now.Add(-100*24*time.Hour))
	mid, midExecs := mkRun("runmid0001", "lab-a", now.Add(-40*24*time.Hour))
	active, activeExecs := mkRun("runact0001", "lab-a", now.Add(-200*24*time.Hour))
	for _, x := range []struct {
		r Run
		e []Execution
	}{{old, oldExecs}, {mid, midExecs}, {active, activeExecs}} {
		if err := s.CreateRun(ctx, x.r, x.e, AuditEvent{Action: "run.create", Outcome: "accepted", Timestamp: x.r.CreatedAt}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Run{old, mid} {
		if err := s.CompleteRun(ctx, r.ID, Completion{Status: RunSucceeded, FinishedAt: r.CreatedAt,
			Executions: []Execution{{CheckID: "1-tcp", Status: "succeeded", Stdout: "secret-ish output", ResultJSON: `{"k":1}`}}}); err != nil {
			t.Fatal(err)
		}
	}
	blanked, deleted, err := s.Purge(ctx, now.Add(-30*24*time.Hour), now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || blanked < 1 {
		t.Errorf("blanked=%d deleted=%d", blanked, deleted)
	}
	if _, _, err := s.GetRun(ctx, old.ID); err != ErrNotFound {
		t.Error("old run should be deleted")
	}
	_, execs, err := s.GetRun(ctx, mid.ID)
	if err != nil || execs[0].Stdout != "" || execs[0].ResultJSON == "" {
		t.Errorf("mid run outputs not blanked or metadata lost: %+v %v", execs, err)
	}
	if _, _, err := s.GetRun(ctx, active.ID); err != nil {
		t.Error("active runs must never be purged")
	}
}
