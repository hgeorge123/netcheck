package k8s

import (
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testJob(t *testing.T) *batchv1.Job {
	t.Helper()
	job, err := BuildJob("payments", testSpec(t), testOpts())
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func list(kv ...string) corev1.ResourceList {
	l := corev1.ResourceList{}
	for i := 0; i < len(kv); i += 2 {
		l[corev1.ResourceName(kv[i])] = resource.MustParse(kv[i+1])
	}
	return l
}

func quota(name string, hard, used corev1.ResourceList, scopes ...corev1.ResourceQuotaScope) corev1.ResourceQuota {
	return corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.ResourceQuotaSpec{Hard: hard, Scopes: scopes},
		Status:     corev1.ResourceQuotaStatus{Hard: hard, Used: used},
	}
}

func TestCheckQuotaRoom(t *testing.T) {
	job := testJob(t) // requests 50m/32Mi, limits 200m/64Mi/16Mi
	cases := []struct {
		name   string
		quotas []corev1.ResourceQuota
		ranges []corev1.LimitRange
		want   string // "" = fits; otherwise a fragment of the message
	}{
		{"no quota", nil, nil, ""},
		{"room left", []corev1.ResourceQuota{quota("compute", list("requests.cpu", "4", "pods", "10"), list("requests.cpu", "1", "pods", "3"))}, nil, ""},
		{"cpu full", []corev1.ResourceQuota{quota("compute", list("requests.cpu", "4"), list("requests.cpu", "3970m"))}, nil,
			"ResourceQuota compute: requests.cpu uses 3970m of 4 and the probe needs 50m"},
		{"plain cpu means requests", []corev1.ResourceQuota{quota("compute", list("cpu", "1"), list("cpu", "1"))}, nil, "cpu uses 1 of 1"},
		{"memory limit full", []corev1.ResourceQuota{quota("mem", list("limits.memory", "1Gi"), list("limits.memory", "1000Mi"))}, nil, "limits.memory uses 1000Mi of 1Gi"},
		{"pod count full", []corev1.ResourceQuota{quota("objects", list("pods", "5"), list("pods", "5"))}, nil, "pods uses 5 of 5"},
		{"job count full", []corev1.ResourceQuota{quota("objects", list("count/jobs.batch", "2"), list("count/jobs.batch", "2"))}, nil, "count/jobs.batch uses 2 of 2"},
		{"ephemeral request defaults to the limit", []corev1.ResourceQuota{quota("disk", list("requests.ephemeral-storage", "100Mi"), list("requests.ephemeral-storage", "90Mi"))}, nil,
			"requests.ephemeral-storage uses 90Mi of 100Mi and the probe needs 16Mi"},
		{"other resources ignored", []corev1.ResourceQuota{quota("storage", list("requests.storage", "1Gi", "services", "1"), list("requests.storage", "1Gi", "services", "1"))}, nil, ""},
		{"terminating scope does not match the probe Pod", []corev1.ResourceQuota{quota("t", list("pods", "0"), nil, corev1.ResourceQuotaScopeTerminating)}, nil, ""},
		{"not best effort scope matches", []corev1.ResourceQuota{quota("nbe", list("pods", "0"), nil, corev1.ResourceQuotaScopeNotBestEffort)}, nil, "pods uses 0 of 0"},
		{"best effort scope does not match", []corev1.ResourceQuota{quota("be", list("pods", "0"), nil, corev1.ResourceQuotaScopeBestEffort)}, nil, ""},
		{"container minimum", nil, []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "limits"},
			Spec:       corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{Type: corev1.LimitTypeContainer, Min: list("cpu", "100m")}}},
		}}, "LimitRange limits: container cpu request 50m is below the minimum 100m"},
		{"container maximum", nil, []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "limits"},
			Spec:       corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{Type: corev1.LimitTypeContainer, Max: list("memory", "48Mi")}}},
		}}, "container memory limit 64Mi is above the maximum 48Mi"},
		{"within limit range", nil, []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "limits"},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{
				{Type: corev1.LimitTypeContainer, Min: list("cpu", "10m"), Max: list("cpu", "1")},
				{Type: corev1.LimitTypePod, Min: list("memory", "16Mi"), Max: list("memory", "1Gi")},
			}},
		}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckQuotaRoom(job, tc.quotas, tc.ranges)
			if tc.want == "" && got != "" {
				t.Fatalf("probe should fit, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("message %q does not contain %q", got, tc.want)
			}
		})
	}
}

func TestQuotaScopeSelectorIsSkipped(t *testing.T) {
	q := quota("prio", list("pods", "0"), nil)
	q.Spec.ScopeSelector = &corev1.ScopeSelector{MatchExpressions: []corev1.ScopedResourceSelectorRequirement{{
		ScopeName: corev1.ResourceQuotaScopePriorityClass, Operator: corev1.ScopeSelectorOpIn, Values: []string{"high"},
	}}}
	if msg := CheckQuotaRoom(testJob(t), []corev1.ResourceQuota{q}, nil); msg != "" {
		t.Fatalf("a quota with a scope selector must be skipped, got %q", msg)
	}
}
