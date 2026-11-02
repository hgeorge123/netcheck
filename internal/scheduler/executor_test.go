package scheduler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/k8s"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// fakeJobs is an in-memory JobAPI. It only exists in tests: the binaries
// never fabricate connectivity results.
type fakeJobs struct {
	mu        sync.Mutex
	jobs      map[string]*batchv1.Job
	pods      map[string][]corev1.Pod // by run id
	logs      map[string]string       // by pod name
	createErr error
	onCreate  func(f *fakeJobs, job *batchv1.Job)
	deleted   []string
	policies  []networkingv1.NetworkPolicy
	sas       map[string]*corev1.ServiceAccount
}

func newFakeJobs() *fakeJobs {
	return &fakeJobs{jobs: map[string]*batchv1.Job{}, pods: map[string][]corev1.Pod{}, logs: map[string]string{},
		sas: map[string]*corev1.ServiceAccount{}}
}

var saGR = schema.GroupResource{Resource: "serviceaccounts"}

func (f *fakeJobs) ListNamespaces(context.Context) ([]corev1.Namespace, error) { return nil, nil }

func (f *fakeJobs) GetServiceAccount(_ context.Context, ns, name string) (*corev1.ServiceAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sa, ok := f.sas[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(saGR, name)
	}
	return sa.DeepCopy(), nil
}

func (f *fakeJobs) CreateServiceAccount(_ context.Context, sa *corev1.ServiceAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sas[key(sa.Namespace, sa.Name)] = sa.DeepCopy()
	return nil
}

func key(ns, name string) string { return ns + "/" + name }

var jobGR = schema.GroupResource{Group: "batch", Resource: "jobs"}

func (f *fakeJobs) CreateJob(_ context.Context, job *batchv1.Job) error {
	f.mu.Lock()
	if f.createErr != nil {
		f.mu.Unlock()
		return f.createErr
	}
	if _, ok := f.jobs[key(job.Namespace, job.Name)]; ok {
		f.mu.Unlock()
		return apierrors.NewAlreadyExists(jobGR, job.Name)
	}
	job.CreationTimestamp = metav1.Now()
	f.jobs[key(job.Namespace, job.Name)] = job
	hook := f.onCreate
	f.mu.Unlock()
	if hook != nil {
		hook(f, job)
	}
	return nil
}

func (f *fakeJobs) GetJob(_ context.Context, ns, name string) (*batchv1.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(jobGR, name)
	}
	return j.DeepCopy(), nil
}

func (f *fakeJobs) DeleteJob(_ context.Context, ns, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.jobs[key(ns, name)]; !ok {
		return apierrors.NewNotFound(jobGR, name)
	}
	delete(f.jobs, key(ns, name))
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeJobs) ListManagedJobs(_ context.Context, ns string) ([]batchv1.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []batchv1.Job
	for _, j := range f.jobs {
		if j.Namespace == ns && j.Labels[k8s.LabelManagedBy] == k8s.ManagedByValue {
			out = append(out, *j)
		}
	}
	return out, nil
}

func (f *fakeJobs) ListProbePods(_ context.Context, _, runID string) ([]corev1.Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]corev1.Pod(nil), f.pods[runID]...), nil
}

func (f *fakeJobs) ReadPodLogs(_ context.Context, _, pod string, _ int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []byte(f.logs[pod]), nil
}

func (f *fakeJobs) ListNetworkPolicies(context.Context, string) ([]networkingv1.NetworkPolicy, error) {
	return f.policies, nil
}

func (f *fakeJobs) deletedNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

// podWithResult simulates the probe Pod terminating with the given result.
func podWithResult(phase corev1.PodPhase, logs string) func(*fakeJobs, *batchv1.Job) {
	return func(f *fakeJobs, job *batchv1.Job) {
		runID := job.Labels[k8s.LabelRunID]
		name := job.Name + "-abcde"
		f.mu.Lock()
		defer f.mu.Unlock()
		f.pods[runID] = []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: job.Namespace},
			Spec:       corev1.PodSpec{NodeName: "node-1"},
			Status: corev1.PodStatus{Phase: phase, PodIP: "10.1.2.3", HostIP: "172.18.0.9", ContainerStatuses: []corev1.ContainerStatus{{
				Name: k8s.ProbeContainerName, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}},
		}}
		f.logs[name] = logs
	}
}

const runID = "0123456789abcdef0123456789abcdef"

func testSpec(t *testing.T, checks ...probes.CheckRequest) probes.Spec {
	t.Helper()
	pol := probes.DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []probes.PortRange{{From: 80, To: 443}}}.WithBuiltinDenies()
	for i := range checks {
		if checks[i].Method == probes.MethodTCP && checks[i].Port == 0 {
			checks[i].Port = 443
		}
	}
	s, err := probes.BuildSpec(runID, probes.RunRequest{Target: "10.0.0.1", Checks: checks}, pol,
		probes.Limits{MaxChecks: 5, DefaultCheckTimeout: 5 * time.Second, MaxCheckTimeout: 10 * time.Second, MaxJobDuration: 60 * time.Second, MaxOutputBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type env struct {
	ex    *Executor
	jobs  *fakeJobs
	store *store.Store
	lim   *Limiter
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	jobs := newFakeJobs()
	lim := NewLimiter(3, 10)
	ex := &Executor{Store: st, Jobs: jobs, Limiter: lim, ReadFidelity: true, ManageProbeServiceAccount: true,
		PollInterval: time.Millisecond, PodStartGrace: 50 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		JobOptions: k8s.JobOptions{Image: "r/p@sha256:" + strings.Repeat("a", 64), ServiceAccountName: "netcheck-probe", RunAsUser: 65532,
			CPURequest: "50m", CPULimit: "200m", MemoryRequest: "32Mi", MemoryLimit: "64Mi", EphemeralStorageLimit: "16Mi", ActiveDeadlineSeconds: 1, TTLSecondsAfterFinished: 300}}
	return &env{ex: ex, jobs: jobs, store: st, lim: lim}
}

func (e *env) create(t *testing.T, spec probes.Spec) store.Run {
	t.Helper()
	b, _ := json.Marshal(spec)
	run := store.Run{ID: spec.RunID, CreatedAt: time.Now(), ActorID: "u1", Namespace: "payments", ClusterID: "c", Target: spec.Target.Raw,
		Status: store.RunQueued, RequestJSON: "{}", SpecJSON: string(b)}
	var execs []store.Execution
	for i, c := range spec.Checks {
		execs = append(execs, store.Execution{ID: spec.RunID + "-" + c.ID, Seq: i + 1, CheckID: c.ID, Method: string(c.Method), Status: store.RunQueued})
	}
	if err := e.store.CreateRun(context.Background(), run, execs, store.AuditEvent{Action: "run.create", Outcome: "accepted", RunID: run.ID}); err != nil {
		t.Fatal(err)
	}
	return run
}

func (e *env) runSync(t *testing.T, run store.Run, spec probes.Spec) (store.Run, []store.Execution) {
	t.Helper()
	if !e.lim.TryAcquire(run.Namespace) {
		t.Fatal("limiter full")
	}
	e.ex.Start(run, spec)
	e.ex.Wait()
	if ns, total := e.lim.InUse(run.Namespace); ns != 0 || total != 0 {
		t.Fatalf("limiter slot leaked: %d/%d", ns, total)
	}
	r, execs, err := e.store.GetRun(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r, execs
}

func resultLine(t *testing.T, res probes.Result) string {
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return "2026-10-21T00:00:00Z human trace\n" + probes.ResultPrefix + string(b) + "\n"
}

func TestHappyPathPersistsAndCleansUp(t *testing.T) {
	e := newEnv(t)
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP}, probes.CheckRequest{Method: probes.MethodHTTP})
	now := time.Now().UTC()
	res := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID, Source: probes.SourceInfo{PodIP: "10.1.2.3"},
		Checks: []probes.CheckResult{
			{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusSucceeded, Category: diagnostics.CategoryOK, StartedAt: now, FinishedAt: now, DurationMS: 3, UsedIP: "10.0.0.1", Output: "connected", Equivalent: []string{"nc", "-z"}},
			{ID: "2-http", Method: probes.MethodHTTP, Status: probes.StatusSucceeded, Category: diagnostics.CategoryHTTPResponse, StartedAt: now, FinishedAt: now, HTTP: &probes.HTTPResult{StatusCode: 404}},
		}}
	e.jobs.onCreate = podWithResult(corev1.PodSucceeded, resultLine(t, res))
	e.jobs.policies = []networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "deny"}, Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{"Egress"}}}}

	run, execs := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunSucceeded || run.JobName != k8s.JobName(runID) || run.StartedAt == nil || run.FinishedAt == nil {
		t.Fatalf("run = %+v", run)
	}
	if !strings.Contains(run.PolicyFidelity, k8s.FidelityNamespaceWide) {
		t.Errorf("fidelity = %s", run.PolicyFidelity)
	}
	if len(execs) != 2 || execs[0].Status != "succeeded" || execs[0].PodIP != "10.1.2.3" || execs[0].NodeName != "node-1" || execs[0].NodeIP != "172.18.0.9" || !strings.HasSuffix(execs[0].PodName, "-abcde") || execs[0].Stdout != "connected" {
		t.Fatalf("execs = %+v", execs)
	}
	var diag diagnostics.Diagnosis
	if err := json.Unmarshal([]byte(execs[1].DiagnosisJSON), &diag); err != nil || diag.Severity == diagnostics.SeverityError {
		t.Errorf("HTTP 404 diagnosis = %+v (%v)", diag, err)
	}
	if strings.Contains(execs[0].ResultJSON, "connected") {
		t.Error("output must be stored only in stdout so retention can purge it")
	}
	if d := e.jobs.deletedNames(); len(d) != 1 || d[0] != k8s.JobName(runID) {
		t.Errorf("deleted = %v", d)
	}
}

func TestNetworkFailureIsNotInfraError(t *testing.T) {
	e := newEnv(t)
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	now := time.Now().UTC()
	res := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID, Checks: []probes.CheckResult{
		{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusTimedOut, Category: diagnostics.CategoryTimeout, StartedAt: now, FinishedAt: now}}}
	e.jobs.onCreate = podWithResult(corev1.PodSucceeded, resultLine(t, res))
	run, execs := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunFailed || run.FailureCategory != diagnostics.CategoryTimeout || execs[0].Status != "timed_out" {
		t.Fatalf("run = %+v execs = %+v", run, execs)
	}
}

func TestCreateErrorsAreClassified(t *testing.T) {
	cases := []struct {
		err      error
		category string
	}{
		{apierrors.NewForbidden(jobGR, "x", errorString(`pods "x" is forbidden: violates PodSecurity "restricted:latest"`)), diagnostics.CategoryAdmissionRejected},
		{apierrors.NewForbidden(jobGR, "x", errorString(`ValidatingAdmissionPolicy 'netcheck-probe-jobs' denied request`)), diagnostics.CategoryAdmissionRejected},
		{apierrors.NewForbidden(jobGR, "x", errorString(`User "system:serviceaccount:netcheck:netcheck" cannot create resource "jobs"`)), diagnostics.CategoryInfraError},
		{apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "payments"), diagnostics.CategoryInfraError},
	}
	for _, c := range cases {
		e := newEnv(t)
		e.jobs.createErr = c.err
		spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
		run, execs := e.runSync(t, e.create(t, spec), spec)
		if run.Status != store.RunInfraError || run.FailureCategory != c.category || execs[0].Status != store.RunInfraError || run.ErrorMessage == "" {
			t.Errorf("%v: run = %+v", c.err, run)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestImagePullBackOffIsInfraErrorAndCleaned(t *testing.T) {
	e := newEnv(t)
	e.jobs.onCreate = func(f *fakeJobs, job *batchv1.Job) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.pods[runID] = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Status: corev1.PodStatus{Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "probe", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "denied"}}}}}}}
	}
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run, _ := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunInfraError || !strings.Contains(run.ErrorMessage, "ImagePullBackOff") {
		t.Fatalf("run = %+v", run)
	}
	if len(e.jobs.deletedNames()) != 1 {
		t.Error("job not cleaned after infra failure")
	}
}

func TestNoPodCreatedReportsAdmission(t *testing.T) {
	e := newEnv(t)
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run, _ := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunInfraError || run.FailureCategory != diagnostics.CategoryAdmissionRejected {
		t.Fatalf("run = %+v", run)
	}
}

func TestInvalidOrMissingOutput(t *testing.T) {
	e := newEnv(t)
	e.jobs.onCreate = podWithResult(corev1.PodSucceeded, "just text, no structured line\n")
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run, _ := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunInfraError || run.FailureCategory != diagnostics.CategoryProbeOutputInvalid {
		t.Fatalf("run = %+v", run)
	}

	e2 := newEnv(t)
	spec2 := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP}, probes.CheckRequest{Method: probes.MethodHTTP})
	now := time.Now()
	partial := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID, Checks: []probes.CheckResult{
		{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusSucceeded, Category: "ok", StartedAt: now, FinishedAt: now}}}
	e2.jobs.onCreate = podWithResult(corev1.PodSucceeded, resultLine(t, partial))
	run, execs := e2.runSync(t, e2.create(t, spec2), spec2)
	if run.Status != store.RunInfraError || execs[0].Status != "succeeded" || execs[1].Status != store.RunInfraError {
		t.Fatalf("partial: run = %+v execs = %+v", run, execs)
	}
}

func TestParseResultRejectsForeignRun(t *testing.T) {
	line := resultLine(t, probes.Result{SchemaVersion: probes.SchemaVersion, RunID: "ffffffffffffffff"})
	if _, err := ParseResult([]byte(line), runID); err == nil {
		t.Error("result of another run accepted")
	}
	// The last structured line wins (a spoofed earlier line is ignored).
	spoof := probes.ResultPrefix + `{"schemaVersion":"x"}` + "\n" + resultLine(t, probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID})
	if _, err := ParseResult([]byte(spoof), runID); err != nil {
		t.Errorf("last line not used: %v", err)
	}
}

func TestCredentialsInProbeAreAudited(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	res := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID, Source: probes.SourceInfo{SATokenMounted: true},
		Checks: []probes.CheckResult{{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusSucceeded, Category: "ok", StartedAt: now, FinishedAt: now}}}
	e.jobs.onCreate = podWithResult(corev1.PodSucceeded, resultLine(t, res))
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	e.runSync(t, e.create(t, spec), spec)
	evs, err := e.store.ListAudit(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range evs {
		found = found || (ev.Action == "probe.credentials_detected" && ev.Outcome == "violation")
	}
	if !found {
		t.Errorf("violation not audited: %+v", evs)
	}
}

func TestNoKubernetesMeansInfraErrorNotFakeResult(t *testing.T) {
	e := newEnv(t)
	e.ex.Jobs = nil
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run, execs := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunInfraError || execs[0].Status != store.RunInfraError {
		t.Fatalf("run = %+v", run)
	}
}

func TestShutdownLeavesRunForRecovery(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.ex.Ctx = ctx
	e.ex.PodStartGrace = time.Hour
	e.jobs.onCreate = func(*fakeJobs, *batchv1.Job) { cancel() }
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run, _ := e.runSync(t, e.create(t, spec), spec)
	if run.Status != store.RunQueued && run.Status != store.RunRunning {
		t.Fatalf("run was finalised on shutdown: %+v", run)
	}
}

func TestRecoverResumesExistingJobAndClosesLostOnes(t *testing.T) {
	e := newEnv(t)
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	run := e.create(t, spec)
	if err := e.store.MarkRunning(context.Background(), run.ID, k8s.JobName(run.ID), "", time.Now()); err != nil {
		t.Fatal(err)
	}
	// The Job survived the restart and its Pod already finished.
	job, _ := k8s.BuildJob("payments", spec, e.ex.JobOptions)
	now := time.Now()
	res := probes.Result{SchemaVersion: probes.SchemaVersion, RunID: runID, Checks: []probes.CheckResult{
		{ID: "1-tcp", Method: probes.MethodTCP, Status: probes.StatusSucceeded, Category: "ok", StartedAt: now, FinishedAt: now}}}
	e.jobs.onCreate = podWithResult(corev1.PodSucceeded, resultLine(t, res))
	if err := e.jobs.CreateJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	lostSpec := spec
	lostSpec.RunID = "ffffffffffffffffffffffffffffffff"
	lost := e.create(t, lostSpec)

	if err := e.ex.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.ex.Wait()
	got, _, _ := e.store.GetRun(context.Background(), run.ID)
	if got.Status != store.RunSucceeded {
		t.Errorf("resumed run = %+v", got)
	}
	gotLost, _, _ := e.store.GetRun(context.Background(), lost.ID)
	if gotLost.Status != store.RunInfraError || !strings.Contains(gotLost.ErrorMessage, "restarted") {
		t.Errorf("lost run = %+v", gotLost)
	}
	if ns, total := e.lim.InUse("payments"); ns != 0 || total != 0 {
		t.Errorf("limiter leaked after recovery: %d/%d", ns, total)
	}
}

func TestReconcileOrphans(t *testing.T) {
	e := newEnv(t)
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})
	active := e.create(t, spec)
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	mk := func(name, id string) *batchv1.Job {
		return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "payments", CreationTimestamp: old,
			Labels: map[string]string{k8s.LabelManagedBy: k8s.ManagedByValue, k8s.LabelRunID: id}}}
	}
	e.jobs.jobs[key("payments", "netcheck-active")] = mk("netcheck-active", active.ID)
	e.jobs.jobs[key("payments", "netcheck-unknown")] = mk("netcheck-unknown", "deadbeefdeadbeef")
	e.jobs.jobs[key("payments", "foreign")] = &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "payments", CreationTimestamp: old}}
	e.ex.ReconcileOrphans(context.Background(), []string{"payments"})
	d := e.jobs.deletedNames()
	if len(d) != 1 || d[0] != "netcheck-unknown" {
		t.Errorf("deleted = %v (active and foreign jobs must be kept)", d)
	}
}

func TestProbeServiceAccountHandling(t *testing.T) {
	spec := testSpec(t, probes.CheckRequest{Method: probes.MethodTCP})

	// mode=all: created on demand with the safe shape.
	e := newEnv(t)
	e.runSync(t, e.create(t, spec), spec)
	sa, err := e.jobs.GetServiceAccount(context.Background(), "payments", "netcheck-probe")
	if err != nil || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		t.Fatalf("probe SA not created safely: %+v %v", sa, err)
	}

	// An existing SA with an IRSA role is refused before any Job is created.
	e2 := newEnv(t)
	irsa := k8s.ProbeServiceAccount("payments", "netcheck-probe")
	irsa.Annotations = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/admin"}
	e2.jobs.sas[key("payments", "netcheck-probe")] = irsa
	run, _ := e2.runSync(t, e2.create(t, spec), spec)
	if run.Status != store.RunInfraError || !strings.Contains(run.ErrorMessage, "IRSA") || len(e2.jobs.jobs) != 0 {
		t.Fatalf("IRSA service account not refused: %+v", run)
	}

	// mode=list: a missing SA is reported, never created.
	e3 := newEnv(t)
	e3.ex.ManageProbeServiceAccount = false
	run, _ = e3.runSync(t, e3.create(t, spec), spec)
	if run.Status != store.RunInfraError || !strings.Contains(run.ErrorMessage, "helm upgrade") || len(e3.jobs.sas) != 0 {
		t.Fatalf("list mode: %+v", run)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, 3)
	if !l.TryAcquire("a") || !l.TryAcquire("a") || l.TryAcquire("a") {
		t.Error("per-namespace limit not enforced")
	}
	if !l.TryAcquire("b") || l.TryAcquire("c") {
		t.Error("global limit not enforced")
	}
	l.Release("a")
	if !l.TryAcquire("c") {
		t.Error("release did not free a slot")
	}
	l.Release("zzz") // releasing an unknown namespace must not underflow
	if _, total := l.InUse("a"); total != 3 {
		t.Errorf("total = %d", total)
	}
}
