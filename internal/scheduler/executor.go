package scheduler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/k8s"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

const (
	maxLogBytes       = 1 << 20
	maxErrorMessage   = 1024
	waitGrace         = 30 * time.Second
	orphanMinAge      = 2 * time.Minute
	cleanupTimeout    = 15 * time.Second
	defaultPoll       = time.Second
	defaultPodStart   = 30 * time.Second
	actionRunComplete = "run.complete"
)

// Fatal container waiting reasons: the probe will never start.
var fatalWaitingReasons = []string{"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError"}

// Executor drives runs. Ctx is cancelled on shutdown; runs interrupted by
// shutdown stay queued/running and are resumed by Recover on next start.
type Executor struct {
	Ctx          context.Context
	Store        *store.Store
	Jobs         k8s.JobAPI // nil when the Kubernetes API is not configured
	Limiter      *Limiter
	JobOptions   k8s.JobOptions
	ReadFidelity bool
	// ManageProbeServiceAccount creates the probe ServiceAccount on demand
	// (namespaceScope.mode=all). In list mode Helm creates it.
	ManageProbeServiceAccount bool
	PollInterval              time.Duration
	PodStartGrace             time.Duration
	Log                       *slog.Logger

	wg sync.WaitGroup
}

func (e *Executor) ctx() context.Context {
	if e.Ctx != nil {
		return e.Ctx
	}
	return context.Background()
}

func (e *Executor) poll() time.Duration {
	if e.PollInterval > 0 {
		return e.PollInterval
	}
	return defaultPoll
}

func (e *Executor) podStartGrace() time.Duration {
	if e.PodStartGrace > 0 {
		return e.PodStartGrace
	}
	return defaultPodStart
}

// Start executes run asynchronously. The caller must already hold a Limiter
// slot for run.Namespace; Start releases it when the run finishes.
func (e *Executor) Start(run store.Run, spec probes.Spec) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.Limiter.Release(run.Namespace)
		e.execute(e.ctx(), run, spec, false)
	}()
}

// Wait blocks until all in-flight runs have returned.
func (e *Executor) Wait() { e.wg.Wait() }

type failure struct {
	category string
	message  string
}

func truncateMsg(s string) string {
	if len(s) > maxErrorMessage {
		return s[:maxErrorMessage] + "…"
	}
	return s
}

func (e *Executor) execute(ctx context.Context, run store.Run, spec probes.Spec, resume bool) {
	log := e.Log.With("run_id", run.ID, "namespace", run.Namespace)
	jobName := k8s.JobName(run.ID)

	if e.Jobs == nil {
		e.fail(run, jobName, failure{diagnostics.CategoryInfraError, "The Kubernetes API is not configured in the controller; no check was run."}, false)
		return
	}

	fidelity := run.PolicyFidelity
	if !resume {
		if fl := e.ensureProbeServiceAccount(ctx, run.Namespace); fl != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("probe service account not usable", "message", fl.message)
			e.fail(run, jobName, *fl, false)
			return
		}
		fidelity = e.fidelity(ctx, run)
		job, err := k8s.BuildJob(run.Namespace, spec, e.JobOptions)
		if err != nil {
			e.fail(run, jobName, failure{diagnostics.CategoryInfraError, "Could not build the Job: " + err.Error()}, false)
			return
		}
		if msg := e.quotaRoom(ctx, job); msg != "" {
			log.Warn("no quota room for the probe", "message", msg)
			e.fail(run, jobName, failure{diagnostics.CategoryAdmissionRejected, truncateMsg(msg)}, false)
			return
		}
		if err := e.Jobs.CreateJob(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
			if ctx.Err() != nil {
				return // shutdown: Recover decides on next start
			}
			log.Warn("job creation failed", "error", err)
			e.fail(run, jobName, classifyCreateError(err), false)
			return
		}
		log.Info("job created", "job", jobName)
	}
	if err := e.Store.MarkRunning(ctx, run.ID, jobName, fidelity, time.Now()); err != nil && ctx.Err() == nil {
		log.Error("mark running failed", "error", err)
	}

	pod, fl := e.wait(ctx, run, jobName)
	if ctx.Err() != nil {
		log.Info("shutdown while waiting; run will be recovered", "job", jobName)
		return
	}
	if fl != nil {
		log.Warn("run infrastructure failure", "category", fl.category, "message", fl.message)
		e.fail(run, jobName, *fl, true)
		return
	}
	e.collect(ctx, run, spec, jobName, pod)
}

// quotaRoom checks the ResourceQuotas and LimitRanges of the source
// namespace before the Job is created, so a full quota is reported at once
// and by name. When they cannot be read (older RBAC) the check is skipped and
// Kubernetes still enforces them.
func (e *Executor) quotaRoom(ctx context.Context, job *batchv1.Job) string {
	quotas, err := e.Jobs.ListResourceQuotas(ctx, job.Namespace)
	if err != nil {
		e.Log.Debug("resource quotas not readable; check skipped", "namespace", job.Namespace, "error", err)
		return ""
	}
	ranges, err := e.Jobs.ListLimitRanges(ctx, job.Namespace)
	if err != nil {
		e.Log.Debug("limit ranges not readable; check skipped", "namespace", job.Namespace, "error", err)
		ranges = nil
	}
	return k8s.CheckQuotaRoom(job, quotas, ranges)
}

// ensureProbeServiceAccount verifies (and in mode=all creates) the dedicated
// probe ServiceAccount, refusing one that could carry credentials.
func (e *Executor) ensureProbeServiceAccount(ctx context.Context, namespace string) *failure {
	name := e.JobOptions.ServiceAccountName
	sa, err := e.Jobs.GetServiceAccount(ctx, namespace, name)
	if apierrors.IsNotFound(err) {
		if !e.ManageProbeServiceAccount {
			return &failure{diagnostics.CategoryInfraError, fmt.Sprintf("ServiceAccount %s is missing in namespace %s; run helm upgrade with that namespace in the list.", name, namespace)}
		}
		if err := e.Jobs.CreateServiceAccount(ctx, k8s.ProbeServiceAccount(namespace, name)); err != nil && !apierrors.IsAlreadyExists(err) {
			return &failure{diagnostics.CategoryInfraError, truncateMsg("Could not create the probe ServiceAccount: " + err.Error())}
		}
		e.Log.Info("probe service account created", "namespace", namespace, "name", name)
		if sa, err = e.Jobs.GetServiceAccount(ctx, namespace, name); err != nil {
			return &failure{diagnostics.CategoryInfraError, truncateMsg("Could not read the probe ServiceAccount: " + err.Error())}
		}
	} else if err != nil {
		return &failure{diagnostics.CategoryInfraError, truncateMsg("Could not read the probe ServiceAccount: " + err.Error())}
	}
	if err := k8s.CheckProbeServiceAccount(sa); err != nil {
		return &failure{diagnostics.CategoryInfraError, err.Error()}
	}
	return nil
}

func (e *Executor) fidelity(ctx context.Context, run store.Run) string {
	if !e.ReadFidelity {
		return ""
	}
	var f k8s.Fidelity
	pols, err := e.Jobs.ListNetworkPolicies(ctx, run.Namespace)
	if err != nil {
		f = k8s.Fidelity{Level: k8s.FidelityUnknown, EgressPolicies: []k8s.PolicyRef{},
			Notes: []string{"Could not read the namespace NetworkPolicies: " + truncateMsg(err.Error())}}
	} else {
		f = k8s.EvaluateFidelity(pols, k8s.ProbeLabels(run.ID))
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func classifyCreateError(err error) failure {
	msg := truncateMsg(err.Error())
	switch {
	case apierrors.IsForbidden(err) && strings.Contains(msg, "cannot create resource"):
		return failure{diagnostics.CategoryInfraError, "The controller has no RBAC permission to create Jobs in this namespace: " + msg}
	case apierrors.IsForbidden(err), apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
		return failure{diagnostics.CategoryAdmissionRejected, "The cluster rejected the Job: " + msg}
	case apierrors.IsNotFound(err):
		return failure{diagnostics.CategoryInfraError, "The namespace does not exist or is not accessible: " + msg}
	default:
		return failure{diagnostics.CategoryInfraError, "Error creating the Job: " + msg}
	}
}

func newestPod(pods []corev1.Pod) *corev1.Pod {
	if len(pods) == 0 {
		return nil
	}
	p := pods[0]
	for _, x := range pods[1:] {
		if x.CreationTimestamp.After(p.CreationTimestamp.Time) {
			p = x
		}
	}
	return &p
}

func pendingReason(p *corev1.Pod) (reason string, fatal bool) {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && w.Reason != "" {
			return w.Reason + ": " + w.Message, slices.Contains(fatalWaitingReasons, w.Reason)
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			return c.Reason + ": " + c.Message, false
		}
	}
	return "", false
}

// wait polls Job and Pod state until the probe Pod terminates, a fatal
// condition is detected or the deadline expires.
func (e *Executor) wait(ctx context.Context, run store.Run, jobName string) (*corev1.Pod, *failure) {
	deadline := time.Duration(e.JobOptions.ActiveDeadlineSeconds)*time.Second + waitGrace
	wctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	start := time.Now()
	lastReason := ""
	ticker := time.NewTicker(e.poll())
	defer ticker.Stop()
	for {
		job, err := e.Jobs.GetJob(wctx, run.Namespace, jobName)
		switch {
		case apierrors.IsNotFound(err):
			return nil, &failure{diagnostics.CategoryInfraError, "The Job disappeared before the result was collected."}
		case err != nil:
			e.Log.Debug("get job failed, retrying", "run_id", run.ID, "error", err)
		default:
			pods, err := e.Jobs.ListProbePods(wctx, run.Namespace, run.ID)
			if err != nil {
				e.Log.Debug("list pods failed, retrying", "run_id", run.ID, "error", err)
				break
			}
			if p := newestPod(pods); p != nil {
				if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
					return p, nil
				}
				reason, fatal := pendingReason(p)
				if fatal {
					return nil, &failure{diagnostics.CategoryInfraError, truncateMsg("The probe could not start: " + reason)}
				}
				if reason != "" {
					lastReason = reason
				}
			} else if time.Since(start) > e.podStartGrace() {
				return nil, &failure{diagnostics.CategoryAdmissionRejected, "The Job created no Pod: possibly rejected by Pod Security Admission, ResourceQuota, LimitRange or a webhook. Check the Job events."}
			}
			for _, c := range job.Status.Conditions {
				if c.Type == "Failed" && c.Status == corev1.ConditionTrue {
					msg := "The Job failed without a probe result: " + c.Reason + " " + c.Message
					if lastReason != "" {
						msg += " (last Pod state: " + lastReason + ")"
					}
					return nil, &failure{diagnostics.CategoryInfraError, truncateMsg(msg)}
				}
			}
		}
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return nil, nil
			}
			msg := "Timed out without a probe result."
			if lastReason != "" {
				msg += " Last Pod state: " + lastReason
			}
			return nil, &failure{diagnostics.CategoryInfraError, truncateMsg(msg)}
		case <-ticker.C:
		}
	}
}

// ParseResult extracts the last structured result line from probe logs.
func ParseResult(logs []byte, runID string) (probes.Result, error) {
	var last []byte
	sc := bufio.NewScanner(bytes.NewReader(logs))
	sc.Buffer(make([]byte, 64<<10), maxLogBytes)
	for sc.Scan() {
		if line := sc.Bytes(); bytes.HasPrefix(line, []byte(probes.ResultPrefix)) {
			last = append(last[:0], line[len(probes.ResultPrefix):]...)
		}
	}
	if err := sc.Err(); err != nil {
		return probes.Result{}, fmt.Errorf("reading logs: %w", err)
	}
	if last == nil {
		return probes.Result{}, errors.New("no NETCHECK_RESULT line in probe output")
	}
	var res probes.Result
	if err := json.Unmarshal(last, &res); err != nil {
		return probes.Result{}, fmt.Errorf("invalid result JSON: %w", err)
	}
	if res.SchemaVersion != probes.SchemaVersion {
		return probes.Result{}, fmt.Errorf("unexpected schemaVersion %q", res.SchemaVersion)
	}
	if res.Error == "" && res.RunID != runID {
		return probes.Result{}, errors.New("result belongs to a different run")
	}
	return res, nil
}

func exitCode(p *corev1.Pod) *int {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name == k8s.ProbeContainerName && cs.State.Terminated != nil {
			v := int(cs.State.Terminated.ExitCode)
			return &v
		}
	}
	return nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func (e *Executor) collect(ctx context.Context, run store.Run, spec probes.Spec, jobName string, pod *corev1.Pod) {
	log := e.Log.With("run_id", run.ID, "namespace", run.Namespace)
	logs, err := e.Jobs.ReadPodLogs(ctx, run.Namespace, pod.Name, maxLogBytes)
	if err != nil {
		e.fail(run, jobName, failure{diagnostics.CategoryInfraError, truncateMsg("Could not read the probe logs: " + err.Error())}, true)
		return
	}
	res, err := ParseResult(logs, run.ID)
	if err != nil {
		e.fail(run, jobName, failure{diagnostics.CategoryProbeOutputInvalid, truncateMsg("Invalid probe output: " + err.Error())}, true)
		return
	}
	if res.Error != "" {
		e.fail(run, jobName, failure{diagnostics.CategoryInfraError, truncateMsg("The probe rejected the spec: " + res.Error)}, true)
		return
	}

	podIP, node := pod.Status.PodIP, pod.Spec.NodeName
	if podIP == "" {
		podIP = res.Source.PodIP
	}
	if node == "" {
		node = res.Source.NodeName
	}
	byID := map[string]probes.CheckResult{}
	for _, c := range res.Checks {
		byID[c.ID] = c
	}
	code := exitCode(pod)
	var execs []store.Execution
	status, failCat := store.RunSucceeded, ""
	missing := false
	for _, c := range spec.Checks {
		cr, ok := byID[c.ID]
		if !ok || cr.Method != c.Method {
			missing = true
			continue
		}
		httpStatus := 0
		if cr.HTTP != nil {
			httpStatus = cr.HTTP.StatusCode
		}
		diag := diagnostics.Diagnose(string(cr.Method), cr.Category, httpStatus)
		out := cr.Output
		cr.Output = "" // stored separately so retention can purge it
		started, finished := cr.StartedAt, cr.FinishedAt
		dur := cr.DurationMS
		execs = append(execs, store.Execution{
			CheckID: c.ID, Status: cr.Status, Category: cr.Category, ArgvJSON: mustJSON(cr.Equivalent),
			StartedAt: &started, FinishedAt: &finished, DurationMS: &dur, ExitCode: code,
			Stdout: out, Stderr: cr.Error, ResolvedIPsJSON: mustJSON(cr.ResolvedIPs), UsedIP: cr.UsedIP,
			PodIP: podIP, NodeName: node, NodeIP: pod.Status.HostIP, PodName: pod.Name, JobName: jobName, DiagnosisJSON: mustJSON(diag), ResultJSON: mustJSON(cr),
		})
		if cr.Status != probes.StatusSucceeded && status == store.RunSucceeded {
			status, failCat = store.RunFailed, cr.Category
		}
	}
	comp := store.Completion{Status: status, FailureCategory: failCat, FinishedAt: time.Now(), Executions: execs}
	if missing {
		comp.Status = store.RunInfraError
		comp.FailureCategory = diagnostics.CategoryProbeOutputInvalid
		comp.ErrorMessage = "The probe did not return a result for every check."
		comp.ExecutionFallbackStatus = store.RunInfraError
	}
	details := mustJSON(map[string]any{"job": jobName, "pod": pod.Name, "podIp": podIP, "node": node,
		"resolver": res.Resolver, "settledMs": res.SettledMS, "saTokenMounted": res.Source.SATokenMounted,
		"cloudCredentialsHint": res.Source.CloudCredentialsHint})
	comp.Audit = append(comp.Audit, store.AuditEvent{ActorID: "system:controller", Action: actionRunComplete,
		Namespace: run.Namespace, RunID: run.ID, Outcome: comp.Status, DetailsJSON: details})
	if res.Source.SATokenMounted || res.Source.CloudCredentialsHint {
		log.Error("SECURITY: credentials detected inside probe pod", "pod", pod.Name)
		comp.Audit = append(comp.Audit, store.AuditEvent{ActorID: "system:controller", Action: "probe.credentials_detected",
			Namespace: run.Namespace, RunID: run.ID, Outcome: "violation", DetailsJSON: details})
	}
	if err := e.Store.CompleteRun(ctx, run.ID, comp); err != nil {
		// Keep the Job: Recover/reconcile can collect it again.
		log.Error("persisting result failed; job kept for recovery", "error", err)
		return
	}
	log.Info("run completed", "status", comp.Status, "failure_category", comp.FailureCategory)
	e.cleanup(run, jobName)
}

// fail persists an infrastructure failure, then deletes the Job if one may exist.
func (e *Executor) fail(run store.Run, jobName string, f failure, jobExists bool) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	err := e.Store.CompleteRun(ctx, run.ID, store.Completion{
		Status: store.RunInfraError, FailureCategory: f.category, ErrorMessage: f.message, FinishedAt: time.Now(),
		ExecutionFallbackStatus: store.RunInfraError,
		Audit: []store.AuditEvent{{ActorID: "system:controller", Action: actionRunComplete, Namespace: run.Namespace,
			RunID: run.ID, Outcome: store.RunInfraError, DetailsJSON: mustJSON(map[string]string{"category": f.category, "job": jobName})}},
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		e.Log.Error("persisting failure failed", "run_id", run.ID, "error", err)
		return
	}
	if jobExists {
		e.cleanup(run, jobName)
	}
}

func (e *Executor) cleanup(run store.Run, jobName string) {
	if e.Jobs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	err := e.Jobs.DeleteJob(ctx, run.Namespace, jobName)
	if err != nil && !apierrors.IsNotFound(err) {
		e.Log.Warn("job cleanup failed; reconciler will retry", "run_id", run.ID, "job", jobName, "error", err)
		_ = e.Store.InsertAudit(ctx, store.AuditEvent{ActorID: "system:controller", Action: "job.cleanup", Namespace: run.Namespace,
			RunID: run.ID, Outcome: "failed", DetailsJSON: mustJSON(map[string]string{"job": jobName, "error": truncateMsg(err.Error())})})
	}
}

// Recover resumes or closes runs left queued/running by a previous process.
// It must run before the API starts accepting requests.
func (e *Executor) Recover(ctx context.Context) error {
	runs, err := e.Store.ListActiveRuns(ctx)
	if err != nil {
		return err
	}
	for _, run := range runs {
		jobName := k8s.JobName(run.ID)
		var spec probes.Spec
		if err := json.Unmarshal([]byte(run.SpecJSON), &spec); err != nil {
			e.fail(run, jobName, failure{diagnostics.CategoryInfraError, "Invalid stored spec during recovery."}, false)
			continue
		}
		if e.Jobs == nil {
			e.fail(run, jobName, failure{diagnostics.CategoryInfraError, "The controller restarted without access to the Kubernetes API."}, false)
			continue
		}
		_, err := e.Jobs.GetJob(ctx, run.Namespace, jobName)
		switch {
		case apierrors.IsNotFound(err):
			e.fail(run, jobName, failure{diagnostics.CategoryInfraError, "The controller restarted and the Job no longer exists; there is no result to collect."}, false)
		case err != nil:
			e.fail(run, jobName, failure{diagnostics.CategoryInfraError, truncateMsg("Error reading the Job during recovery: " + err.Error())}, true)
		default:
			e.Log.Info("resuming run after restart", "run_id", run.ID, "job", jobName)
			e.Limiter.ForceAcquire(run.Namespace)
			e.wg.Add(1)
			go func(run store.Run, spec probes.Spec) {
				defer e.wg.Done()
				defer e.Limiter.Release(run.Namespace)
				e.execute(e.ctx(), run, spec, true)
			}(run, spec)
		}
	}
	return nil
}

// ReconcileOrphans deletes managed Jobs whose run is terminal or unknown.
func (e *Executor) ReconcileOrphans(ctx context.Context, namespaces []string) {
	if e.Jobs == nil {
		return
	}
	for _, ns := range namespaces {
		jobs, err := e.Jobs.ListManagedJobs(ctx, ns)
		if err != nil {
			e.Log.Warn("reconcile: list jobs failed", "namespace", ns, "error", err)
			continue
		}
		for _, j := range jobs {
			runID := j.Labels[k8s.LabelRunID]
			if time.Since(j.CreationTimestamp.Time) < orphanMinAge {
				continue
			}
			status, err := e.Store.RunStatus(ctx, runID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				continue
			}
			if status == store.RunQueued || status == store.RunRunning {
				continue
			}
			if err := e.Jobs.DeleteJob(ctx, ns, j.Name); err != nil && !apierrors.IsNotFound(err) {
				e.Log.Warn("reconcile: delete failed", "namespace", ns, "job", j.Name, "error", err)
				continue
			}
			e.Log.Info("reconcile: deleted orphan job", "namespace", ns, "job", j.Name, "run_status", status)
			_ = e.Store.InsertAudit(ctx, store.AuditEvent{ActorID: "system:controller", Action: "job.reconcile_delete",
				Namespace: ns, RunID: runID, Outcome: "deleted", DetailsJSON: mustJSON(map[string]string{"job": j.Name})})
		}
	}
}
