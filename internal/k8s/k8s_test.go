package k8s

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/hgeorge123/netcheck/internal/probes"
)

const testImage = "registry.example.com/netcheck/probe@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testOpts() JobOptions {
	return JobOptions{Image: testImage, ServiceAccountName: "netcheck-probe", RunAsUser: 65532, CPURequest: "50m", CPULimit: "200m",
		MemoryRequest: "32Mi", MemoryLimit: "64Mi", EphemeralStorageLimit: "16Mi", ActiveDeadlineSeconds: 60, TTLSecondsAfterFinished: 300}
}

func testSpec(t *testing.T) probes.Spec {
	t.Helper()
	pol := probes.DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []probes.PortRange{{From: 443, To: 443}}}.WithBuiltinDenies()
	s, err := probes.BuildSpec("0123456789abcdef0123456789abcdef", probes.RunRequest{Target: "10.0.0.1",
		Checks: []probes.CheckRequest{{Method: probes.MethodTCP, Port: 443}, {Method: probes.MethodPing}}}, pol, probes.Limits{MaxChecks: 5,
		DefaultCheckTimeout: 5e9, MaxCheckTimeout: 10e9, MaxJobDuration: 60e9, MaxOutputBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildJobIsHardened(t *testing.T) {
	job, err := BuildJob("payments", testSpec(t), testOpts())
	if err != nil {
		t.Fatal(err)
	}
	js := job.Spec
	pod := js.Template.Spec
	c := pod.Containers[0]
	checks := map[string]bool{
		"name bounded":           len(job.Name) <= 63 && job.Name == "netcheck-0123456789abcdef0123456789abcdef",
		"namespace":              job.Namespace == "payments",
		"backoffLimit 0":         *js.BackoffLimit == 0,
		"activeDeadline":         *js.ActiveDeadlineSeconds == 60,
		"ttl safety net":         *js.TTLSecondsAfterFinished == 300,
		"restart never":          pod.RestartPolicy == corev1.RestartPolicyNever,
		"no sa token":            pod.AutomountServiceAccountToken != nil && !*pod.AutomountServiceAccountToken,
		"dedicated sa":           pod.ServiceAccountName == "netcheck-probe",
		"no service links":       pod.EnableServiceLinks != nil && !*pod.EnableServiceLinks,
		"no host namespaces":     !pod.HostNetwork && !pod.HostPID && !pod.HostIPC,
		"no volumes":             len(pod.Volumes) == 0 && len(c.VolumeMounts) == 0,
		"single container":       len(pod.Containers) == 1 && len(pod.InitContainers) == 0 && len(pod.EphemeralContainers) == 0,
		"image by digest":        c.Image == testImage && strings.Contains(c.Image, "@sha256:"),
		"no command override":    len(c.Command) == 0 && len(c.Args) == 0,
		"runAsNonRoot":           *pod.SecurityContext.RunAsNonRoot && *c.SecurityContext.RunAsNonRoot && *c.SecurityContext.RunAsUser == 65532,
		"seccomp":                pod.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault,
		"no priv escalation":     !*c.SecurityContext.AllowPrivilegeEscalation && !*c.SecurityContext.Privileged,
		"readonly rootfs":        *c.SecurityContext.ReadOnlyRootFilesystem,
		"drop ALL":               len(c.SecurityContext.Capabilities.Drop) == 1 && c.SecurityContext.Capabilities.Drop[0] == "ALL" && len(c.SecurityContext.Capabilities.Add) == 0,
		"limits set":             !c.Resources.Limits.Cpu().IsZero() && !c.Resources.Limits.Memory().IsZero() && !c.Resources.Requests.Cpu().IsZero(),
		"labels":                 job.Labels[LabelRunID] == "0123456789abcdef0123456789abcdef" && js.Template.Labels[LabelPartOf] == "netcheck",
		"terminationGracePeriod": *pod.TerminationGracePeriodSeconds == 5,
		"no envFrom":             len(c.EnvFrom) == 0,
		"only ping sysctl":       len(pod.SecurityContext.Sysctls) == 1 && pod.SecurityContext.Sysctls[0].Name == PingGroupRangeSysctl && pod.SecurityContext.Sysctls[0].Value == "65532 65532",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("hardening check failed: %s", name)
		}
	}
	for _, e := range c.Env {
		if e.ValueFrom != nil && (e.ValueFrom.SecretKeyRef != nil || e.ValueFrom.ConfigMapKeyRef != nil) {
			t.Errorf("env %s references a secret/configmap", e.Name)
		}
	}
	var spec probes.Spec
	if err := json.Unmarshal([]byte(c.Env[0].Value), &spec); err != nil || spec.Validate() != nil {
		t.Errorf("spec env not valid: %v", err)
	}
}

func TestBuildJobRejectsInvalidInput(t *testing.T) {
	s := testSpec(t)
	s.RunID = "Bad_ID"
	if _, err := BuildJob("payments", s, testOpts()); err == nil {
		t.Error("invalid run id accepted")
	}
	o := testOpts()
	o.MemoryLimit = "lots"
	if _, err := BuildJob("payments", testSpec(t), o); err == nil {
		t.Error("invalid quantity accepted")
	}
}

func TestClientAgainstFakeClientset(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	c := &Client{CS: cs}
	job, _ := BuildJob("payments", testSpec(t), testOpts())
	if err := c.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	other := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "payments"}}
	if _, err := cs.BatchV1().Jobs("payments").Create(ctx, other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := c.ListManagedJobs(ctx, "payments")
	if err != nil || len(jobs) != 1 || jobs[0].Name != job.Name {
		t.Fatalf("managed jobs = %v %v", jobs, err)
	}
	if err := c.DeleteJob(ctx, "payments", job.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetJob(ctx, "payments", job.Name); err == nil {
		t.Error("job not deleted")
	}
}

func np(name string, sel metav1.LabelSelector, types ...networkingv1.PolicyType) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: networkingv1.NetworkPolicySpec{PodSelector: sel, PolicyTypes: types}}
}

func TestEvaluateFidelity(t *testing.T) {
	lbl := ProbeLabels("0123456789abcdef")
	if f := EvaluateFidelity(nil, lbl); f.Level != FidelityNoEgressPolicy {
		t.Errorf("none = %s", f.Level)
	}
	ingressOnly := []networkingv1.NetworkPolicy{np("ing", metav1.LabelSelector{}, networkingv1.PolicyTypeIngress)}
	if f := EvaluateFidelity(ingressOnly, lbl); f.Level != FidelityNoEgressPolicy {
		t.Errorf("ingress only = %s", f.Level)
	}
	wide := []networkingv1.NetworkPolicy{np("deny-all", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress),
		np("allow-dns", metav1.LabelSelector{}, networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress)}
	f := EvaluateFidelity(wide, lbl)
	if f.Level != FidelityNamespaceWide || len(f.EgressPolicies) != 2 || !f.EgressPolicies[0].SelectsProbe {
		t.Errorf("wide = %+v", f)
	}
	if got := f.EgressPolicies[0].PodSelector; got != "{} (all Pods)" {
		t.Errorf("empty selector rendered as %q (must not read as <none>)", got)
	}
	specific := append(wide, np("app-only", metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments-api"}}, networkingv1.PolicyTypeEgress))
	f = EvaluateFidelity(specific, lbl)
	if f.Level != FidelitySpecific || f.EgressPolicies[2].SelectsProbe || f.EgressPolicies[2].PodSelector != "app=payments-api" {
		t.Errorf("specific = %+v", f)
	}
	// Implicit Egress via egress rules without policyTypes.
	implicit := np("implicit", metav1.LabelSelector{})
	implicit.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
	if f := EvaluateFidelity([]networkingv1.NetworkPolicy{implicit}, lbl); f.Level != FidelityNamespaceWide {
		t.Errorf("implicit = %s", f.Level)
	}
	for _, n := range f.Notes {
		if strings.Contains(n, "equivalent") {
			t.Error("fidelity notes must not claim equivalence")
		}
	}
}
