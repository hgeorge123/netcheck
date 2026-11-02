package k8s

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StaticNamespaces is the namespace source for namespaceScope.mode=list.
type StaticNamespaces []string

// Available implements auth.NamespaceSource.
func (s StaticNamespaces) Available(context.Context) ([]string, error) {
	out := slices.Clone([]string(s))
	slices.Sort(out)
	return out, nil
}

// All returns every configured namespace (same as Available in list mode).
func (s StaticNamespaces) All(ctx context.Context) ([]string, error) { return s.Available(ctx) }

// ClusterNamespaces lists live namespaces (namespaceScope.mode=all), so new
// namespaces become available without redeploying. Results are cached.
type ClusterNamespaces struct {
	API     JobAPI
	Exclude []string
	TTL     time.Duration

	mu      sync.Mutex
	cached  []string // available (without Exclude)
	all     []string // every live namespace
	fetched time.Time
}

// Available implements auth.NamespaceSource.
func (c *ClusterNamespaces) Available(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	return slices.Clone(c.cached), nil
}

// All returns every live namespace, including excluded and system ones (for
// the administration page).
func (c *ClusterNamespaces) All(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	return slices.Clone(c.all), nil
}

// refresh updates the cache when it is older than TTL. Callers hold c.mu.
func (c *ClusterNamespaces) refresh(ctx context.Context) error {
	if c.cached != nil && time.Since(c.fetched) < c.TTL {
		return nil
	}
	if c.API == nil {
		return errors.New("kubernetes API not configured")
	}
	list, err := c.API.ListNamespaces(ctx)
	if err != nil {
		if c.cached != nil {
			return nil // serve stale data on transient errors
		}
		return err
	}
	out, all := make([]string, 0, len(list)), make([]string, 0, len(list))
	for _, ns := range list {
		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		all = append(all, ns.Name)
		if !slices.Contains(c.Exclude, ns.Name) {
			out = append(out, ns.Name)
		}
	}
	slices.Sort(out)
	slices.Sort(all)
	c.cached, c.all, c.fetched = out, all, time.Now()
	return nil
}

// ProbeServiceAccount is the dedicated identity created on demand in
// namespaceScope.mode=all. The admission policy only accepts this shape.
func ProbeServiceAccount(namespace, name string) *corev1.ServiceAccount {
	f := false
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			LabelPartOf: PartOfValue, LabelComponent: ComponentProbe, LabelManagedBy: ManagedByValue}},
		AutomountServiceAccountToken: &f,
	}
}

// CheckProbeServiceAccount refuses service accounts that could hand cloud
// or Kubernetes credentials to the probe.
func CheckProbeServiceAccount(sa *corev1.ServiceAccount) error {
	for k := range sa.Annotations {
		if strings.HasPrefix(k, "eks.amazonaws.com/") {
			return fmt.Errorf("ServiceAccount %s/%s has annotation %q (IRSA): the probe would receive AWS credentials", sa.Namespace, sa.Name, k)
		}
	}
	if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		return fmt.Errorf("ServiceAccount %s/%s does not set automountServiceAccountToken: false", sa.Namespace, sa.Name)
	}
	// imagePullSecrets are used by the kubelet only and never reach the Pod.
	if len(sa.Secrets) > 0 {
		return fmt.Errorf("ServiceAccount %s/%s references token Secrets; the probe must have none", sa.Namespace, sa.Name)
	}
	return nil
}
