package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

func checkTypesFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	h, err := LoadCheckTypes(context.Background(), f.store, nil, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.srv.CheckTypes = h
	return f
}

func catalogMethods(t *testing.T, f *fixture) ([]string, bool) {
	t.Helper()
	rec := f.do(f.user, "GET", "/api/v1/probes/catalog", "")
	var body struct {
		Items        []probes.CatalogEntry `json:"items"`
		FirewallMode bool                  `json:"firewallMode"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("catalog: %d %s", rec.Code, rec.Body)
	}
	out := []string{}
	for _, e := range body.Items {
		out = append(out, string(e.Method))
	}
	return out, body.FirewallMode
}

func TestCheckTypesDisabledForEverybody(t *testing.T) {
	f := checkTypesFixture(t)
	if got, fw := catalogMethods(t, f); len(got) != len(probes.Catalog) || !fw {
		t.Fatalf("default catalog = %v firewall=%v, want every type", got, fw)
	}
	// Only administrators change it.
	if rec := f.do(f.user, "PUT", "/api/v1/admin/check-types", `{"disabled":["traceroute"]}`); rec.Code != http.StatusForbidden {
		t.Errorf("user PUT: %d", rec.Code)
	}
	rec := f.do(f.admin, "PUT", "/api/v1/admin/check-types", `{"disabled":["traceroute","firewall","ping"]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"type":"traceroute","enabled":false}`) {
		t.Fatalf("admin PUT: %d %s", rec.Code, rec.Body)
	}
	got, fw := catalogMethods(t, f)
	if slices.Contains(got, "traceroute") || slices.Contains(got, "ping") || !slices.Contains(got, "tcp") || fw {
		t.Errorf("catalog after disabling = %v firewall=%v", got, fw)
	}
	// A run with a disabled check is refused (also for administrators) and names the check.
	for _, who := range []string{f.user, f.admin} {
		rec := f.do(who, "POST", "/api/v1/runs", `{"namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":443},{"method":"ping"}]}`)
		if rec.Code != http.StatusForbidden || errCode(t, rec) != "check_type_disabled" || !strings.Contains(rec.Body.String(), `"field":"checks[1]"`) {
			t.Errorf("run with ping: %d %s", rec.Code, rec.Body)
		}
	}
	// The firewall ticket mode is refused even with enabled checks only.
	rec = f.do(f.user, "POST", "/api/v1/runs", `{"mode":"firewall","namespace":"payments","target":"10.1.2.3","checks":[{"method":"tcp","port":443}]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"field":"mode"`) {
		t.Errorf("firewall mode: %d %s", rec.Code, rec.Body)
	}
	// Enabled checks still run.
	if rec := f.do(f.user, "POST", "/api/v1/runs", validRun); rec.Code != http.StatusAccepted {
		t.Errorf("valid run: %d %s", rec.Code, rec.Body)
	}
}

func TestCheckTypesValidation(t *testing.T) {
	f := checkTypesFixture(t)
	for body, code := range map[string]string{
		`{"disabled":["telnet"]}`: "unknown_check_type",
		`{"disabled":["dns","tcp","udp","http","https","ping","traceroute"]}`: "all_checks_disabled",
	} {
		rec := f.do(f.admin, "PUT", "/api/v1/admin/check-types", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestCheckTypesManagedByHelm(t *testing.T) {
	f := newFixture(t)
	h, err := LoadCheckTypes(context.Background(), f.store, []string{"udp"}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.srv.CheckTypes = h
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/check-types", `{"disabled":[]}`); rec.Code != http.StatusConflict {
		t.Errorf("PUT with helm-managed check types: %d", rec.Code)
	}
	if got, _ := catalogMethods(t, f); slices.Contains(got, "udp") {
		t.Errorf("udp offered although disabled in Helm: %v", got)
	}
}

func TestLoadCheckTypesSeedsOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "c.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := LoadCheckTypes(ctx, st, []string{"ping", "nope"}, true, time.Now()); err == nil {
		t.Error("unknown type in the seed accepted")
	}
	h, err := LoadCheckTypes(ctx, st, []string{"traceroute", "ping"}, true, time.Now())
	if err != nil || h.Enabled("ping") || !h.Enabled("tcp") {
		t.Fatalf("seed: %v ping=%v", err, h.Enabled("ping"))
	}
	// The database wins over a changed seed once it exists.
	h, err = LoadCheckTypes(ctx, st, nil, true, time.Now())
	if err != nil || h.Enabled("traceroute") {
		t.Errorf("stored setting lost: %v traceroute=%v", err, h.Enabled("traceroute"))
	}
	// A nil holder allows everything (servers built without it).
	var none *CheckTypes
	if !none.Enabled("ping") || len(none.Check(probes.RunRequest{Mode: "firewall", Checks: []probes.CheckRequest{{Method: "ping"}}})) != 0 {
		t.Error("nil holder must allow every type")
	}
}
