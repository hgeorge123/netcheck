package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

func TestAdminEditsDestinationPolicy(t *testing.T) {
	f := newFixture(t)
	// Regular users cannot read or change the policy.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/admin/policy", ""},
		{"PUT", "/api/v1/admin/policy", `{"allowCidrs":["0.0.0.0/0"]}`},
		{"POST", "/api/v1/admin/policy/check", `{"target":"8.8.8.8"}`},
	} {
		if rec := f.do(f.user, c.method, c.path, c.body); rec.Code != http.StatusForbidden {
			t.Errorf("user %s %s: %d", c.method, c.path, rec.Code)
		}
	}

	// The fixture policy only allows 10.0.0.0/8: a public destination is denied.
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"8.8.8.8","checks":[{"method":"tcp","port":443}]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("public IP before the change: %d %s", rec.Code, rec.Body)
	}
	rec := f.do(f.admin, "POST", "/api/v1/admin/policy/check", `{"target":"8.8.8.8","port":443}`)
	if !strings.Contains(rec.Body.String(), `"allowed":false`) || !strings.Contains(rec.Body.String(), "not in any allowed range") {
		t.Errorf("check before: %s", rec.Body)
	}

	// Invalid entries are rejected with the field that failed.
	for body, field := range map[string]string{
		`{"allowCidrs":["10.0.0.0/99"]}`:                                    "allowCidrs",
		`{"allowCidrs":["0.0.0.0/0"],"allowHostnameSuffixes":["bad host"]}`: "allowHostnameSuffixes",
		`{"allowCidrs":["0.0.0.0/0"],"allowPorts":[{"from":10,"to":5}]}`:    "allowPorts",
	} {
		rec := f.do(f.admin, "PUT", "/api/v1/admin/policy", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Errorf("PUT %s: %d %s", body, rec.Code, rec.Body)
		}
	}

	// Open the policy: the change applies to the next run without restarting.
	open := `{"allowCidrs":["0.0.0.0/0","::/0"],"denyCidrs":[],"allowHostnameSuffixes":["*"],"allowPorts":[{"from":1,"to":65535}]}`
	rec = f.do(f.admin, "PUT", "/api/v1/admin/policy", open)
	var view policyView
	json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || view.UpdatedBy != "admin" || !view.Editable || !view.ProtectPlatformDestinations {
		t.Fatalf("PUT open: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"www.google.com","checks":[{"method":"tcp","port":443}]}`); rec.Code != http.StatusAccepted {
		t.Errorf("public hostname after opening: %d %s", rec.Code, rec.Body)
	}
	// Platform protections cannot be removed from the web.
	if rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"169.254.169.254","checks":[{"method":"tcp","port":80}]}`); rec.Code != http.StatusForbidden {
		t.Errorf("metadata after opening: %d %s", rec.Code, rec.Body)
	}
	rec = f.do(f.admin, "POST", "/api/v1/admin/policy/check", `{"target":"169.254.169.254","port":80}`)
	if !strings.Contains(rec.Body.String(), `"allowed":false`) {
		t.Errorf("metadata check: %s", rec.Body)
	}

	// The change is persisted and audited.
	stored, err := f.store.GetDestinationPolicy(context.Background())
	if err != nil || !strings.Contains(stored.PolicyJSON, "0.0.0.0/0") {
		t.Errorf("stored: %+v %v", stored, err)
	}
	events, _ := f.store.ListAudit(context.Background(), "")
	n := 0
	for _, ev := range events {
		if ev.Action == "policy.update" && strings.Contains(ev.DetailsJSON, `"before"`) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("policy.update audit events = %d", n)
	}
}

func TestPolicyManagedByHelmIsReadOnly(t *testing.T) {
	f := newFixture(t)
	f.srv.Policies = NewDestinationPolicies(probes.DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}}, nil, false)
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/policy", `{"allowCidrs":["0.0.0.0/0"]}`); rec.Code != http.StatusConflict {
		t.Errorf("PUT with helm-managed policy: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/policy", ""); !strings.Contains(rec.Body.String(), `"managedBy":"helm"`) {
		t.Errorf("GET: %s", rec.Body)
	}
}

func TestLoadDestinationPoliciesSeedsOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seed := probes.DestinationPolicy{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []probes.PortRange{{From: 443, To: 443}}}
	h, err := LoadDestinationPolicies(ctx, st, seed, probes.BuiltinDenyCIDRs, true, time.Now())
	if err != nil || h.Effective().AllowCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("first load: %v", err)
	}
	// An admin change survives restarts even if the Helm values differ.
	stored := store.StoredPolicy{PolicyJSON: `{"allowCidrs":["0.0.0.0/0"]}`, UpdatedAt: time.Now(), UpdatedBy: "alice"}
	st.SaveDestinationPolicy(ctx, stored, store.AuditEvent{Action: "policy.update"})
	h, err = LoadDestinationPolicies(ctx, st, seed, probes.BuiltinDenyCIDRs, true, time.Now())
	if err != nil || h.Effective().AllowCIDRs[0] != "0.0.0.0/0" {
		t.Fatalf("reload: %+v %v", h.Effective(), err)
	}
	if !strings.Contains(strings.Join(h.Effective().DenyCIDRs, ","), "169.254.0.0/16") {
		t.Errorf("platform denies missing: %v", h.Effective().DenyCIDRs)
	}
	// helm mode ignores the database copy.
	h, _ = LoadDestinationPolicies(ctx, st, seed, nil, false, time.Now())
	if h.Effective().AllowCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("helm mode must use the values: %v", h.Effective())
	}
}

// The API server is denied by its exact addresses once they are detected;
// until then (or when they cannot be read) the fallback ranges stay denied.
func TestAPIServerDeniedFailClosed(t *testing.T) {
	h := NewDestinationPolicies(probes.DestinationPolicy{AllowCIDRs: []string{"0.0.0.0/0"}, AllowPorts: []probes.PortRange{{From: 1, To: 65535}}},
		[]string{"172.20.0.1/32"}, true)
	h.SetAPIServerFallback([]string{"107.246.201.192/26", "172.20.0.0/16"})
	denied := func(ip string) bool {
		c, err := h.Effective().Compile()
		if err != nil {
			t.Fatal(err)
		}
		return c.CheckIP(netip.MustParseAddr(ip)) != nil
	}
	// Not detected yet: the whole fallback ranges are denied.
	for _, ip := range []string{"107.246.201.207", "172.20.10.5", "172.20.0.1"} {
		if !denied(ip) {
			t.Errorf("%s allowed before detection", ip)
		}
	}
	// An empty detection is ignored (fail closed).
	if h.SetAPIServerAddresses(nil) || !denied("107.246.201.207") {
		t.Error("empty detection opened the fallback ranges")
	}
	// Detected: only the exact addresses (and the configured denies) remain.
	if !h.SetAPIServerAddresses([]string{"107.246.201.210/32"}) {
		t.Error("first detection not reported as a change")
	}
	if h.SetAPIServerAddresses([]string{"107.246.201.210/32"}) {
		t.Error("same addresses reported as a change")
	}
	for ip, want := range map[string]bool{"107.246.201.210": true, "172.20.0.1": true, "107.246.201.207": false, "172.20.10.5": false} {
		if got := denied(ip); got != want {
			t.Errorf("%s denied=%v, want %v", ip, got, want)
		}
	}
	if got := strings.Join(h.platformDenies(), ","); got != "172.20.0.1/32,107.246.201.210/32" {
		t.Errorf("platform denies shown to administrators = %s", got)
	}
}
