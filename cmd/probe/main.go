// Command probe is the structured network probe executed inside an ephemeral
// Job in the source namespace. It reads an immutable spec from the
// NETCHECK_SPEC environment variable, re-validates it, runs the checks with Go
// network primitives (no shell, no external binaries) and prints the result
// as the last stdout line prefixed with "NETCHECK_RESULT ".
//
// Exit codes: 0 = all checks executed (whatever the network outcome),
// 2 = invalid spec, 3 = internal error.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/probes/runner"
)

const maxSpecBytes = 64 << 10

func main() {
	os.Exit(run())
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
}

func emit(res probes.Result) int {
	b, err := json.Marshal(res)
	if err != nil {
		logf("cannot encode result: %v", err)
		return 3
	}
	fmt.Fprintf(os.Stdout, "%s%s\n", probes.ResultPrefix, b)
	return 0
}

func run() int {
	raw := os.Getenv(probes.SpecEnvVar)
	if raw == "" || len(raw) > maxSpecBytes {
		logf("missing or oversized %s", probes.SpecEnvVar)
		emit(probes.Result{SchemaVersion: probes.SchemaVersion, Error: "invalid spec: missing or oversized"})
		return 2
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var spec probes.Spec
	if err := dec.Decode(&spec); err != nil {
		logf("invalid spec: %v", err)
		emit(probes.Result{SchemaVersion: probes.SchemaVersion, Error: "invalid spec: malformed JSON"})
		return 2
	}
	if err := spec.Validate(); err != nil {
		logf("invalid spec: %v", err)
		emit(probes.Result{SchemaVersion: probes.SchemaVersion, RunID: spec.RunID, Error: "invalid spec: " + runner.Sanitize(err.Error())})
		return 2
	}

	var budget time.Duration
	for _, c := range spec.Checks {
		budget += time.Duration(c.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget+time.Duration(spec.SettleMS)*time.Millisecond+2*time.Second)
	defer cancel()

	r := runner.New(logf)
	res := r.Run(ctx, spec)
	res.Source = runner.DetectSource(os.Getenv, runner.FileExists)
	if content, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		res.Resolver = runner.ParseResolvConf(string(content))
	}
	if res.Source.SATokenMounted || res.Source.CloudCredentialsHint {
		logf("WARNING: credentials detected inside probe Pod; the Job template or admission policy is misconfigured")
	}
	if code := emit(res); code != 0 {
		return code
	}
	return 0
}
