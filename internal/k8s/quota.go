package k8s

import (
	"fmt"
	"sort"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// CheckQuotaRoom tells, before the Job is created, whether the ResourceQuotas
// and LimitRanges of its namespace would reject the probe Pod. It returns a
// message naming the object, the resource and the numbers, or "" when the
// probe fits. Quotas whose scopes it cannot evaluate are skipped: Kubernetes
// still enforces them when the Pod is created.
func CheckQuotaRoom(job *batchv1.Job, quotas []corev1.ResourceQuota, ranges []corev1.LimitRange) string {
	pod := &job.Spec.Template.Spec
	need := podUsage(pod)
	var problems []string
	for _, q := range quotas {
		if !quotaApplies(q, pod) {
			continue
		}
		hard := q.Status.Hard
		if len(hard) == 0 {
			hard = q.Spec.Hard
		}
		for _, name := range sortedNames(hard) {
			want, ok := need[name]
			if !ok {
				continue
			}
			used := q.Status.Used[name]
			total := used.DeepCopy()
			total.Add(want)
			if limit := hard[name]; total.Cmp(limit) > 0 {
				problems = append(problems, fmt.Sprintf("ResourceQuota %s: %s uses %s of %s and the probe needs %s",
					q.Name, name, used.String(), limit.String(), want.String()))
			}
		}
	}
	for _, lr := range ranges {
		problems = append(problems, limitRangeProblems(lr, pod)...)
	}
	if len(problems) == 0 {
		return ""
	}
	return fmt.Sprintf("Namespace %s has no room for the probe Pod (%s). Ask the namespace owner to raise the quota or free resources.",
		job.Namespace, strings.Join(problems, "; "))
}

// podUsage is what the probe Pod and its Job add to quota usage. A missing
// request counts as the limit, as the API server defaults it.
func podUsage(pod *corev1.PodSpec) corev1.ResourceList {
	one := resource.MustParse("1")
	use := corev1.ResourceList{
		corev1.ResourcePods: one,
		"count/pods":        one,
		"count/jobs.batch":  one,
	}
	add := func(name corev1.ResourceName, q resource.Quantity) {
		cur := use[name]
		cur.Add(q)
		use[name] = cur
	}
	for _, c := range pod.Containers {
		for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourceEphemeralStorage} {
			if lim, ok := c.Resources.Limits[r]; ok {
				add("limits."+r, lim)
			}
			req, ok := c.Resources.Requests[r]
			if !ok {
				req, ok = c.Resources.Limits[r]
			}
			if ok {
				add("requests."+r, req)
				add(r, req) // "cpu" and "memory" in a quota mean requests
			}
		}
	}
	return use
}

// quotaApplies evaluates the quota scopes for the probe Pod. Unknown scopes
// and scope selectors make the quota skipped rather than guessed.
func quotaApplies(q corev1.ResourceQuota, pod *corev1.PodSpec) bool {
	if q.Spec.ScopeSelector != nil && len(q.Spec.ScopeSelector.MatchExpressions) > 0 {
		return false
	}
	terminating := pod.ActiveDeadlineSeconds != nil
	for _, s := range q.Spec.Scopes {
		switch s {
		case corev1.ResourceQuotaScopeTerminating:
			if !terminating {
				return false
			}
		case corev1.ResourceQuotaScopeNotTerminating:
			if terminating {
				return false
			}
		case corev1.ResourceQuotaScopeBestEffort:
			return false // the probe always sets requests and limits
		case corev1.ResourceQuotaScopeNotBestEffort:
		default:
			return false
		}
	}
	return true
}

// limitRangeProblems checks the Container and Pod min/max of a LimitRange.
func limitRangeProblems(lr corev1.LimitRange, pod *corev1.PodSpec) []string {
	var out []string
	check := func(kind, what string, value resource.Quantity, name corev1.ResourceName, item corev1.LimitRangeItem) {
		if min, ok := item.Min[name]; ok && value.Cmp(min) < 0 {
			out = append(out, fmt.Sprintf("LimitRange %s: %s %s %s %s is below the minimum %s", lr.Name, kind, name, what, value.String(), min.String()))
		}
		if max, ok := item.Max[name]; ok && value.Cmp(max) > 0 {
			out = append(out, fmt.Sprintf("LimitRange %s: %s %s %s %s is above the maximum %s", lr.Name, kind, name, what, value.String(), max.String()))
		}
	}
	for _, item := range lr.Spec.Limits {
		switch item.Type {
		case corev1.LimitTypeContainer:
			for _, c := range pod.Containers {
				for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourceEphemeralStorage} {
					if v, ok := c.Resources.Requests[name]; ok {
						check("container", "request", v, name, item)
					}
					if v, ok := c.Resources.Limits[name]; ok {
						check("container", "limit", v, name, item)
					}
				}
			}
		case corev1.LimitTypePod:
			// Pod min applies to the sum of requests, max to the sum of limits.
			use := podUsage(pod)
			for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourceEphemeralStorage} {
				if v, ok := use["requests."+name]; ok {
					check("Pod", "request", v, name, corev1.LimitRangeItem{Min: item.Min})
				}
				if v, ok := use["limits."+name]; ok {
					check("Pod", "limit", v, name, corev1.LimitRangeItem{Max: item.Max})
				}
			}
		}
	}
	return out
}

func sortedNames(l corev1.ResourceList) []corev1.ResourceName {
	names := make([]corev1.ResourceName, 0, len(l))
	for n := range l {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}
