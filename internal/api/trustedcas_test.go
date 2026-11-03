package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

func mustTrustedCAs(t *testing.T, st *store.Store) *TrustedCAs {
	t.Helper()
	h, err := LoadTrustedCAs(context.Background(), st, nil, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func caPEM(t *testing.T, name string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAdminTrustedCAs(t *testing.T) {
	f := newFixture(t)
	rec := f.do(f.admin, "GET", "/api/v1/admin/trusted-cas", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"certificates":[]`) || !strings.Contains(rec.Body.String(), `"managedBy":"ui"`) {
		t.Fatalf("empty: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "GET", "/api/v1/admin/trusted-cas", ""); rec.Code != http.StatusForbidden {
		t.Errorf("user GET: %d", rec.Code)
	}
	body := func(certs ...string) string {
		b, _ := json.Marshal(map[string]any{"certificates": certs})
		return string(b)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/trusted-cas", body("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "not_a_certificate") {
		t.Errorf("private key: %d %s", rec.Code, rec.Body)
	}

	// A bundle of two authorities is split and audited by fingerprint.
	corp, proxy := caPEM(t, "Corp Root"), caPEM(t, "Proxy CA")
	rec = f.do(f.admin, "PUT", "/api/v1/admin/trusted-cas", body(corp+proxy))
	var v trustedCAsView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil || len(v.Certificates) != 2 ||
		v.Certificates[1].Subject != "CN=Proxy CA" || len(v.Certificates[0].Fingerprint) != 64 || v.UpdatedBy != "admin" {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	evs, _ := f.store.ListAudit(context.Background(), "")
	audited := false
	for _, ev := range evs {
		if ev.Action == "trusted_cas.update" {
			audited = strings.Contains(ev.DetailsJSON, "CN=Proxy CA") && !strings.Contains(ev.DetailsJSON, "BEGIN CERTIFICATE")
		}
	}
	if !audited {
		t.Error("update not audited by name and fingerprint")
	}

	// Only runs with an HTTPS check carry the authorities.
	spec := func(checks string) probes.Spec {
		t.Helper()
		rec := f.do(f.user, "POST", "/api/v1/runs", `{"namespace":"payments","target":"api.payments.svc.cluster.local","checks":`+checks+`}`)
		var run struct{ ID string }
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &run) != nil {
			t.Fatalf("run: %d %s", rec.Code, rec.Body)
		}
		stored, _, err := f.store.GetRun(context.Background(), run.ID)
		var s probes.Spec
		if err != nil || json.Unmarshal([]byte(stored.SpecJSON), &s) != nil {
			t.Fatalf("stored run: %v", err)
		}
		return s
	}
	if s := spec(`[{"method":"https"}]`); len(s.TrustedCAs) != 2 || s.TrustedCAs[0] != corp {
		t.Errorf("HTTPS run carries %d authorities", len(s.TrustedCAs))
	}
	if s := spec(`[{"method":"tcp","port":443}]`); s.TrustedCAs != nil {
		t.Errorf("TCP run carries %d authorities", len(s.TrustedCAs))
	}

	// Managed in Helm: read-only.
	f.srv.TrustedCAs.editable = false
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/trusted-cas", body()); rec.Code != http.StatusConflict {
		t.Errorf("helm-managed PUT: %d", rec.Code)
	}
}

func TestLoadTrustedCAsSeedsOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	seed := []string{caPEM(t, "Seed CA")}
	// The fixture already stored an empty list: the database wins over the seed.
	h, err := LoadTrustedCAs(ctx, f.store, seed, true, time.Now())
	if err != nil || len(h.view(time.Now()).Certificates) != 0 {
		t.Fatalf("ui-managed reload: %v", err)
	}
	// Managed in Helm: the configuration is authoritative.
	h, err = LoadTrustedCAs(ctx, f.store, seed, false, time.Now())
	if v := h.view(time.Now()); err != nil || len(v.Certificates) != 1 || v.ManagedBy != "helm" {
		t.Fatalf("helm-managed: %+v %v", v, err)
	}
	if _, err := LoadTrustedCAs(ctx, f.store, []string{"garbage"}, false, time.Now()); err == nil {
		t.Error("an invalid seed must stop the start")
	}
}
