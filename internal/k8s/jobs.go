// Package k8s builds the immutable probe Job template, manages its lifecycle
// through client-go and inspects native NetworkPolicies (read-only).
package k8s

import (
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/hgeorge123/netcheck/internal/probes"
)

// Labels applied to every probe Job and Pod.
const (
	LabelPartOf    = "app.kubernetes.io/part-of"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelRunID     = "netcheck.io/run-id"

	PartOfValue    = "netcheck"
	ComponentProbe = "probe"
	ManagedByValue = "netcheck-controller"

	ProbeContainerName = "probe"

	// PingGroupRangeSysctl enables unprivileged ICMP sockets (IPv4 and IPv6).
	PingGroupRangeSysctl = "net.ipv4.ping_group_range"
)

// JobOptions holds the fixed, operator-controlled parts of the template.
type JobOptions struct {
	Image                   string
	ServiceAccountName      string
	RunAsUser               int64
	CPURequest              string
	CPULimit                string
	MemoryRequest           string
	MemoryLimit             string
	EphemeralStorageLimit   string
	ActiveDeadlineSeconds   int64
	TTLSecondsAfterFinished int32
	NodeSelector            map[string]string
}

// JobName returns the deterministic Job name for a run.
func JobName(runID string) string { return "netcheck-" + runID }

// ProbeLabels returns the labels of the probe Pod for runID.
func ProbeLabels(runID string) map[string]string {
	return map[string]string{
		LabelPartOf:    PartOfValue,
		LabelComponent: ComponentProbe,
		LabelManagedBy: ManagedByValue,
		LabelRunID:     runID,
	}
}

func fieldEnv(name, path string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}

// BuildJob renders the probe Job for spec in namespace. Every security
// relevant field is fixed here; nothing comes from user input except the
// validated spec, which is passed as data in an environment variable.
func BuildJob(namespace string, spec probes.Spec, o JobOptions) (*batchv1.Job, error) {
	if !probes.ValidRunID(spec.RunID) {
		return nil, fmt.Errorf("invalid run id")
	}
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	res, err := resources(o)
	if err != nil {
		return nil, err
	}
	f, t := false, true
	backoff := int32(0)
	one := int32(1)
	grace := int64(5)
	labels := ProbeLabels(spec.RunID)

	pod := corev1.PodSpec{
		RestartPolicy:                 corev1.RestartPolicyNever,
		ServiceAccountName:            o.ServiceAccountName,
		AutomountServiceAccountToken:  &f,
		EnableServiceLinks:            &f,
		HostNetwork:                   false,
		HostPID:                       false,
		HostIPC:                       false,
		TerminationGracePeriodSeconds: &grace,
		DNSPolicy:                     corev1.DNSClusterFirst, // same resolver path as regular workloads
		NodeSelector:                  o.NodeSelector,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   &t,
			RunAsUser:      &o.RunAsUser,
			RunAsGroup:     &o.RunAsUser,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			// Safe, namespaced sysctl (allowed by Pod Security "restricted"):
			// lets only the probe group open unprivileged ICMP sockets for
			// ping/traceroute, instead of granting NET_RAW.
			Sysctls: []corev1.Sysctl{{Name: PingGroupRangeSysctl, Value: fmt.Sprintf("%d %d", o.RunAsUser, o.RunAsUser)}},
		},
		Containers: []corev1.Container{{
			Name:            ProbeContainerName,
			Image:           o.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Env: []corev1.EnvVar{
				{Name: probes.SpecEnvVar, Value: string(specJSON)},
				fieldEnv("POD_NAME", "metadata.name"),
				fieldEnv("POD_NAMESPACE", "metadata.namespace"),
				fieldEnv("POD_IP", "status.podIP"),
				fieldEnv("NODE_NAME", "spec.nodeName"),
			},
			Resources:                res,
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &f,
				Privileged:               &f,
				ReadOnlyRootFilesystem:   &t,
				RunAsNonRoot:             &t,
				RunAsUser:                &o.RunAsUser,
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		}},
	}

	deadline := o.ActiveDeadlineSeconds
	ttl := o.TTLSecondsAfterFinished
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: JobName(spec.RunID), Namespace: namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			Completions:             &one,
			Parallelism:             &one,
			ActiveDeadlineSeconds:   &deadline,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       pod,
			},
		},
	}, nil
}

func resources(o JobOptions) (corev1.ResourceRequirements, error) {
	parse := func(name, v string) (resource.Quantity, error) {
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return q, fmt.Errorf("invalid %s %q: %w", name, v, err)
		}
		return q, nil
	}
	var r corev1.ResourceRequirements
	r.Requests, r.Limits = corev1.ResourceList{}, corev1.ResourceList{}
	for _, x := range []struct {
		list corev1.ResourceList
		key  corev1.ResourceName
		name string
		val  string
	}{
		{r.Requests, corev1.ResourceCPU, "cpuRequest", o.CPURequest},
		{r.Requests, corev1.ResourceMemory, "memoryRequest", o.MemoryRequest},
		{r.Limits, corev1.ResourceCPU, "cpuLimit", o.CPULimit},
		{r.Limits, corev1.ResourceMemory, "memoryLimit", o.MemoryLimit},
		{r.Limits, corev1.ResourceEphemeralStorage, "ephemeralStorageLimit", o.EphemeralStorageLimit},
	} {
		q, err := parse(x.name, x.val)
		if err != nil {
			return r, err
		}
		x.list[x.key] = q
	}
	return r, nil
}
