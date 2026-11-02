package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/store"
)

func TestAdminRetention(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(f.user, "GET", "/api/v1/admin/retention", ""); rec.Code != http.StatusForbidden {
		t.Errorf("user GET: %d", rec.Code)
	}
	if rec := f.do(f.user, "PUT", "/api/v1/admin/retention", `{"outputDays":7,"metadataDays":30}`); rec.Code != http.StatusForbidden {
		t.Errorf("user PUT: %d", rec.Code)
	}
	rec := f.do(f.admin, "GET", "/api/v1/admin/retention", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"outputDays":15`) {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}

	for body, field := range map[string]string{
		`{"outputDays":0,"metadataDays":30}`:    "outputDays",
		`{"outputDays":30,"metadataDays":10}`:   "metadataDays",
		`{"outputDays":5,"metadataDays":99999}`: "metadataDays",
	} {
		rec := f.do(f.admin, "PUT", "/api/v1/admin/retention", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Errorf("PUT %s: %d %s", body, rec.Code, rec.Body)
		}
	}

	rec = f.do(f.admin, "PUT", "/api/v1/admin/retention", `{"outputDays":7,"metadataDays":30}`)
	var view retentionView
	json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || view.OutputDays != 7 || view.MetadataDays != 30 || view.UpdatedBy != "admin" {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if o, m := f.srv.Retention.Days(); o != 7 || m != 30 {
		t.Errorf("Days() = %d, %d", o, m)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/system", ""); !strings.Contains(rec.Body.String(), `"metadataDays":30`) {
		t.Errorf("system view: %s", rec.Body)
	}

	stored, err := f.store.GetRetention(context.Background())
	if err != nil || stored.OutputDays != 7 || stored.MetadataDays != 30 {
		t.Errorf("stored: %+v %v", stored, err)
	}
	events, _ := f.store.ListAudit(context.Background(), "")
	n := 0
	for _, ev := range events {
		if ev.Action == "retention.update" && strings.Contains(ev.DetailsJSON, `"before"`) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("retention.update audit events = %d", n)
	}
}

func TestLoadRetentionSeedsOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "r.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := LoadRetention(ctx, st, 15, 45, time.Now())
	if o, m := h.Days(); err != nil || o != 15 || m != 45 {
		t.Fatalf("first load: %d %d %v", o, m, err)
	}
	// An admin change survives restarts even if the Helm values differ.
	st.SaveRetention(ctx, store.StoredRetention{OutputDays: 3, MetadataDays: 10, UpdatedAt: time.Now(), UpdatedBy: "alice"},
		store.AuditEvent{Action: "retention.update"})
	h, err = LoadRetention(ctx, st, 15, 45, time.Now())
	if o, m := h.Days(); err != nil || o != 3 || m != 10 {
		t.Fatalf("reload: %d %d %v", o, m, err)
	}
}
