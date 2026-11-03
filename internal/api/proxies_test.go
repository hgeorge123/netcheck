package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

func mustProxies(t *testing.T, st *store.Store) *Proxies {
	t.Helper()
	h, err := LoadProxies(context.Background(), st, nil, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAdminProxies(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(f.admin, "GET", "/api/v1/admin/proxies", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"proxies":[]`) {
		t.Fatalf("empty: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "PUT", "/api/v1/admin/proxies", `{"proxies":[]}`); rec.Code != http.StatusForbidden {
		t.Errorf("user PUT: %d", rec.Code)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/proxies", `{"proxies":[{"name":"Corp","host":"10.0.0.9","port":3128}]}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "invalid_proxy_name") {
		t.Errorf("bad name: %d %s", rec.Code, rec.Body)
	}
	rec := f.do(f.admin, "PUT", "/api/v1/admin/proxies", `{"proxies":[{"name":"corp","host":"10.0.0.9","port":443},{"name":"outside","host":"192.0.2.10","port":443}]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"updatedBy":"admin"`) {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}

	// Users see the proxies in the catalog to choose one.
	if rec := f.do(f.user, "GET", "/api/v1/probes/catalog", ""); !strings.Contains(rec.Body.String(), `"proxies":[{"name":"corp","host":"10.0.0.9","port":443}`) {
		t.Errorf("catalog: %s", rec.Body)
	}

	create := func(checks string) *httpRecorder {
		r := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"api.payments.svc.cluster.local","checks":`+checks+`}`)
		return &httpRecorder{r.Code, r.Body.String()}
	}
	got := create(`[{"method":"tcp","port":443,"proxy":"corp"},{"method":"https","proxy":"corp"}]`)
	var run struct{ ID string }
	if got.code != http.StatusAccepted || json.Unmarshal([]byte(got.body), &run) != nil {
		t.Fatalf("run through proxy: %d %s", got.code, got.body)
	}
	stored, _, _ := f.store.GetRun(context.Background(), run.ID)
	var spec probes.Spec
	json.Unmarshal([]byte(stored.SpecJSON), &spec)
	if spec.Checks[0].Proxy == nil || spec.Checks[0].Proxy.Address() != "10.0.0.9:443" || spec.Checks[1].Proxy == nil {
		t.Errorf("spec checks = %+v", spec.Checks)
	}
	if got := create(`[{"method":"http","proxy":"corp"}]`); got.code != http.StatusBadRequest || !strings.Contains(got.body, "proxy_not_applicable") {
		t.Errorf("HTTP through proxy: %d %s", got.code, got.body)
	}
	if got := create(`[{"method":"tcp","port":443,"proxy":"nope"}]`); got.code != http.StatusBadRequest || !strings.Contains(got.body, "proxy_unknown") {
		t.Errorf("unknown proxy: %d %s", got.code, got.body)
	}
	// A proxy outside the destination policy is denied like a destination.
	if got := create(`[{"method":"tcp","port":443,"proxy":"outside"}]`); got.code != http.StatusForbidden || !strings.Contains(got.body, "proxy outside") {
		t.Errorf("proxy outside the policy: %d %s", got.code, got.body)
	}

	f.srv.Proxies.editable = false
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/proxies", `{"proxies":[]}`); rec.Code != http.StatusConflict {
		t.Errorf("helm-managed PUT: %d", rec.Code)
	}
}

type httpRecorder struct {
	code int
	body string
}
