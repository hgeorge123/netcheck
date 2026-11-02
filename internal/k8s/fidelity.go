package k8s

import (
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Fidelity levels shown as a badge in the UI.
const (
	FidelityNamespaceWide  = "namespace-wide-likely"
	FidelitySpecific       = "specific-selectors-detected"
	FidelityNoEgressPolicy = "no-native-egress-policies"
	FidelityUnknown        = "unknown"
)

// PolicyRef summarises one egress-relevant NetworkPolicy.
type PolicyRef struct {
	Name         string `json:"name"`
	PodSelector  string `json:"podSelector"`
	SelectsProbe bool   `json:"selectsProbe"`
}

// Fidelity describes how representative the probe Pod is of workloads in
// the namespace with respect to native NetworkPolicy. It is never a claim
// of full equivalence.
type Fidelity struct {
	Level          string      `json:"level"`
	EgressPolicies []PolicyRef `json:"egressPolicies"`
	Notes          []string    `json:"notes"`
}

func affectsEgress(p networkingv1.NetworkPolicy) bool {
	if len(p.Spec.PolicyTypes) == 0 {
		// Kubernetes defaults: Egress is implied only when egress rules exist.
		return len(p.Spec.Egress) > 0
	}
	return slices.Contains(p.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

// EvaluateFidelity classifies the visible egress policies of a namespace
// against the labels of the probe Pod.
func EvaluateFidelity(policies []networkingv1.NetworkPolicy, probeLabels map[string]string) Fidelity {
	f := Fidelity{EgressPolicies: []PolicyRef{}}
	allEmpty := true
	for _, p := range policies {
		if !affectsEgress(p) {
			continue
		}
		empty := len(p.Spec.PodSelector.MatchLabels) == 0 && len(p.Spec.PodSelector.MatchExpressions) == 0
		ref := PolicyRef{Name: p.Name, PodSelector: metav1.FormatLabelSelector(&p.Spec.PodSelector)}
		if empty {
			// FormatLabelSelector prints "<none>" for an empty selector, which
			// reads as "selects nothing"; it actually selects every Pod.
			ref.PodSelector = "{} (all Pods)"
		}
		if sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector); err == nil {
			ref.SelectsProbe = sel.Matches(labels.Set(probeLabels))
		}
		allEmpty = allEmpty && empty
		f.EgressPolicies = append(f.EgressPolicies, ref)
	}
	switch {
	case len(f.EgressPolicies) == 0:
		f.Level = FidelityNoEgressPolicy
		f.Notes = append(f.Notes, "No native egress NetworkPolicies are visible in the source namespace.")
	case allEmpty:
		f.Level = FidelityNamespaceWide
		f.Notes = append(f.Notes, "Every egress policy uses podSelector: {} and also applies to the probe.")
	default:
		f.Level = FidelitySpecific
		f.Notes = append(f.Notes, "Some policies use specific selectors: the probe may not get the same rules as a given workload.")
	}
	f.Notes = append(f.Notes,
		"Cluster-wide policies (ClusterNetworkPolicy in VPC CNI >= 1.21) or CNI-specific controls (e.g. Security Groups for Pods) may exist and are not visible here.",
		"Destination ingress policies, SG/NACL, routes, NAT and proxies also matter.")
	return f
}
