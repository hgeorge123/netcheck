package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func ns(name string, phase corev1.NamespacePhase) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NamespaceStatus{Phase: phase}}
}

func TestClusterNamespacesFiltersAndPicksUpNewOnes(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset(ns("payments", corev1.NamespaceActive), ns("kube-system", corev1.NamespaceActive),
		ns("netcheck", corev1.NamespaceActive), ns("dying", corev1.NamespaceTerminating))
	src := &ClusterNamespaces{API: &Client{CS: cs}, Exclude: []string{"kube-system", "netcheck"}, TTL: time.Millisecond}
	got, err := src.Available(ctx)
	if err != nil || len(got) != 1 || got[0] != "payments" {
		t.Fatalf("available = %v %v", got, err)
	}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, ns("orders", corev1.NamespaceActive), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	got, _ = src.Available(ctx)
	if len(got) != 2 || got[0] != "orders" {
		t.Errorf("new namespace not picked up: %v", got)
	}
}

func TestProbeServiceAccountChecks(t *testing.T) {
	good := ProbeServiceAccount("payments", "netcheck-probe")
	if err := CheckProbeServiceAccount(good); err != nil {
		t.Fatalf("own SA rejected: %v", err)
	}
	irsa := good.DeepCopy()
	irsa.Annotations = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/x"}
	tok := good.DeepCopy()
	tok.AutomountServiceAccountToken = nil
	sec := good.DeepCopy()
	sec.Secrets = []corev1.ObjectReference{{Name: "legacy-token"}}
	for name, sa := range map[string]*corev1.ServiceAccount{"irsa": irsa, "automount": tok, "secrets": sec} {
		if CheckProbeServiceAccount(sa) == nil {
			t.Errorf("%s: unsafe service account accepted", name)
		}
	}
	pull := good.DeepCopy()
	pull.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "registry"}}
	if err := CheckProbeServiceAccount(pull); err != nil {
		t.Errorf("imagePullSecrets never reach the Pod and must be allowed: %v", err)
	}
}
