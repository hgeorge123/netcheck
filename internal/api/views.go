package api

import (
	"encoding/json"
	"time"

	"github.com/hgeorge123/netcheck/internal/store"
)

// RunSummary is the list representation of a run.
type RunSummary struct {
	ID              string     `json:"id"`
	CreatedAt       time.Time  `json:"createdAt"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	Actor           string     `json:"actor"`
	Namespace       string     `json:"namespace"`
	Target          string     `json:"target"`
	Status          string     `json:"status"`
	FailureCategory string     `json:"failureCategory,omitempty"`
}

// ExecutionView is the API representation of one check.
type ExecutionView struct {
	CheckID     string          `json:"checkId"`
	Method      string          `json:"method"`
	Status      string          `json:"status"`
	Category    string          `json:"category,omitempty"`
	StartedAt   *time.Time      `json:"startedAt,omitempty"`
	FinishedAt  *time.Time      `json:"finishedAt,omitempty"`
	DurationMS  *int64          `json:"durationMs,omitempty"`
	ExitCode    *int            `json:"exitCode,omitempty"`
	Output      string          `json:"output"`
	Error       string          `json:"error,omitempty"`
	Equivalent  json.RawMessage `json:"equivalentArgv"`
	ResolvedIPs json.RawMessage `json:"resolvedIps"`
	UsedIP      string          `json:"usedIp,omitempty"`
	PodIP       string          `json:"podIp,omitempty"`
	NodeName    string          `json:"nodeName,omitempty"`
	NodeIP      string          `json:"nodeIp,omitempty"`
	PodName     string          `json:"podName,omitempty"`
	JobName     string          `json:"jobName,omitempty"`
	Diagnosis   json.RawMessage `json:"diagnosis,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

// RunDetail is the API representation of a run with its checks.
type RunDetail struct {
	RunSummary
	ClusterID    string          `json:"clusterId"`
	StartedAt    *time.Time      `json:"startedAt,omitempty"`
	ActorID      string          `json:"actorId"`
	JobName      string          `json:"jobName,omitempty"`
	ErrorMessage string          `json:"errorMessage,omitempty"`
	Request      json.RawMessage `json:"request"`
	Fidelity     json.RawMessage `json:"fidelity,omitempty"`
	Checks       []ExecutionView `json:"checks"`
}

func summary(r store.Run) RunSummary {
	return RunSummary{ID: r.ID, CreatedAt: r.CreatedAt, FinishedAt: r.FinishedAt, Actor: r.ActorDisplay, Namespace: r.Namespace,
		Target: r.Target, Status: r.Status, FailureCategory: r.FailureCategory}
}

func raw(s, fallback string) json.RawMessage {
	if s == "" || !json.Valid([]byte(s)) {
		if fallback == "" {
			return nil
		}
		return json.RawMessage(fallback)
	}
	return json.RawMessage(s)
}

func detail(r store.Run, execs []store.Execution) RunDetail {
	d := RunDetail{RunSummary: summary(r), ClusterID: r.ClusterID, StartedAt: r.StartedAt, ActorID: r.ActorID, JobName: r.JobName,
		ErrorMessage: r.ErrorMessage, Request: raw(r.RequestJSON, "{}"), Fidelity: raw(r.PolicyFidelity, ""), Checks: []ExecutionView{}}
	for _, e := range execs {
		d.Checks = append(d.Checks, ExecutionView{
			CheckID: e.CheckID, Method: e.Method, Status: e.Status, Category: e.Category, StartedAt: e.StartedAt, FinishedAt: e.FinishedAt,
			DurationMS: e.DurationMS, ExitCode: e.ExitCode, Output: e.Stdout, Error: e.Stderr, Equivalent: raw(e.ArgvJSON, "[]"),
			ResolvedIPs: raw(e.ResolvedIPsJSON, "[]"), UsedIP: e.UsedIP, PodIP: e.PodIP, NodeName: e.NodeName, NodeIP: e.NodeIP, PodName: e.PodName, JobName: e.JobName,
			Diagnosis: raw(e.DiagnosisJSON, ""), Result: raw(e.ResultJSON, ""),
		})
	}
	return d
}
