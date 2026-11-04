package k8s

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The API server publishes its own addresses in this EndpointSlice: the
// backends of the "kubernetes" Service. On EKS they are the control plane
// network interfaces, on AKS the API server address.
const (
	apiServerSliceNamespace = "default"
	apiServerSliceName      = "kubernetes"
)

// APIServerAddresses returns the exact addresses of the Kubernetes API server
// as host prefixes (/32 or /128), sorted and without duplicates. It needs
// only "get" on the EndpointSlice default/kubernetes.
func APIServerAddresses(ctx context.Context, cs kubernetes.Interface) ([]string, error) {
	slice, err := cs.DiscoveryV1().EndpointSlices(apiServerSliceNamespace).Get(ctx, apiServerSliceName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ep := range slice.Endpoints {
		for _, a := range ep.Addresses {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return nil, fmt.Errorf("endpointslice %s/%s: invalid address %q", apiServerSliceNamespace, apiServerSliceName, a)
			}
			out = append(out, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("endpointslice %s/%s has no addresses", apiServerSliceNamespace, apiServerSliceName)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
