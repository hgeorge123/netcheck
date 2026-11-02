package k8s

import (
	"context"
	"io"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// JobAPI is the minimal Kubernetes surface the controller uses. It mirrors
// the namespaced RBAC granted by the Helm chart and nothing more.
type JobAPI interface {
	CreateJob(ctx context.Context, job *batchv1.Job) error
	GetJob(ctx context.Context, namespace, name string) (*batchv1.Job, error)
	DeleteJob(ctx context.Context, namespace, name string) error
	ListManagedJobs(ctx context.Context, namespace string) ([]batchv1.Job, error)
	ListProbePods(ctx context.Context, namespace, runID string) ([]corev1.Pod, error)
	ReadPodLogs(ctx context.Context, namespace, pod string, limitBytes int64) ([]byte, error)
	ListNetworkPolicies(ctx context.Context, namespace string) ([]networkingv1.NetworkPolicy, error)
	ListNamespaces(ctx context.Context) ([]corev1.Namespace, error)
	GetServiceAccount(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, sa *corev1.ServiceAccount) error
	ListResourceQuotas(ctx context.Context, namespace string) ([]corev1.ResourceQuota, error)
	ListLimitRanges(ctx context.Context, namespace string) ([]corev1.LimitRange, error)
}

// Client implements JobAPI with client-go.
type Client struct {
	CS kubernetes.Interface
}

var _ JobAPI = (*Client)(nil)

// CreateJob implements JobAPI.
func (c *Client) CreateJob(ctx context.Context, job *batchv1.Job) error {
	_, err := c.CS.BatchV1().Jobs(job.Namespace).Create(ctx, job, metav1.CreateOptions{FieldManager: ManagedByValue})
	return err
}

// GetJob implements JobAPI.
func (c *Client) GetJob(ctx context.Context, namespace, name string) (*batchv1.Job, error) {
	return c.CS.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
}

// DeleteJob deletes the Job and, in the background, its Pods.
func (c *Client) DeleteJob(ctx context.Context, namespace, name string) error {
	policy := metav1.DeletePropagationBackground
	return c.CS.BatchV1().Jobs(namespace).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &policy})
}

// ListManagedJobs lists only Jobs created by this controller.
func (c *Client) ListManagedJobs(ctx context.Context, namespace string) ([]batchv1.Job, error) {
	sel := labels.SelectorFromSet(labels.Set{LabelPartOf: PartOfValue, LabelManagedBy: ManagedByValue}).String()
	list, err := c.CS.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ListProbePods lists the Pods of one run.
func (c *Client) ListProbePods(ctx context.Context, namespace, runID string) ([]corev1.Pod, error) {
	sel := labels.SelectorFromSet(labels.Set{LabelRunID: runID, LabelManagedBy: ManagedByValue}).String()
	list, err := c.CS.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ReadPodLogs reads at most limitBytes of the probe container logs.
func (c *Client) ReadPodLogs(ctx context.Context, namespace, pod string, limitBytes int64) ([]byte, error) {
	req := c.CS.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: ProbeContainerName, LimitBytes: &limitBytes})
	rc, err := req.Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limitBytes))
}

// ListNamespaces lists cluster namespaces (namespaceScope.mode=all only).
func (c *Client) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	list, err := c.CS.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// GetServiceAccount reads one ServiceAccount.
func (c *Client) GetServiceAccount(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error) {
	return c.CS.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
}

// CreateServiceAccount creates the probe ServiceAccount.
func (c *Client) CreateServiceAccount(ctx context.Context, sa *corev1.ServiceAccount) error {
	_, err := c.CS.CoreV1().ServiceAccounts(sa.Namespace).Create(ctx, sa, metav1.CreateOptions{FieldManager: ManagedByValue})
	return err
}

// ListResourceQuotas lists the quotas of a namespace (read-only).
func (c *Client) ListResourceQuotas(ctx context.Context, namespace string) ([]corev1.ResourceQuota, error) {
	list, err := c.CS.CoreV1().ResourceQuotas(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ListLimitRanges lists the LimitRanges of a namespace (read-only).
func (c *Client) ListLimitRanges(ctx context.Context, namespace string) ([]corev1.LimitRange, error) {
	list, err := c.CS.CoreV1().LimitRanges(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ListNetworkPolicies lists native NetworkPolicies (read-only).
func (c *Client) ListNetworkPolicies(ctx context.Context, namespace string) ([]networkingv1.NetworkPolicy, error) {
	list, err := c.CS.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}
