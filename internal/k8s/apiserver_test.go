package k8s

import (
	"context"
	"slices"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func apiServerSlice(addrs ...[]string) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}, AddressType: discoveryv1.AddressTypeIPv4}
	for _, a := range addrs {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{Addresses: a})
	}
	return s
}

func TestAPIServerAddressesAreExactHosts(t *testing.T) {
	cs := fake.NewSimpleClientset(apiServerSlice([]string{"107.246.201.210"}, []string{"10.72.2.70", "107.246.201.210"}))
	got, err := APIServerAddresses(context.Background(), cs)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.72.2.70/32", "107.246.201.210/32"}; !slices.Equal(got, want) {
		t.Errorf("addresses = %v, want %v (sorted, no duplicates, host prefixes)", got, want)
	}
}

func TestAPIServerAddressesIPv6(t *testing.T) {
	cs := fake.NewSimpleClientset(apiServerSlice([]string{"fd00:10::1"}))
	got, err := APIServerAddresses(context.Background(), cs)
	if err != nil || !slices.Equal(got, []string{"fd00:10::1/128"}) {
		t.Errorf("addresses = %v, %v", got, err)
	}
}

func TestAPIServerAddressesErrors(t *testing.T) {
	for name, cs := range map[string]*fake.Clientset{
		"missing":      fake.NewSimpleClientset(),
		"no addresses": fake.NewSimpleClientset(apiServerSlice()),
		"bad address":  fake.NewSimpleClientset(apiServerSlice([]string{"not-an-ip"})),
	} {
		if got, err := APIServerAddresses(context.Background(), cs); err == nil {
			t.Errorf("%s: got %v, want an error (the caller keeps the denied ranges)", name, got)
		}
	}
}
