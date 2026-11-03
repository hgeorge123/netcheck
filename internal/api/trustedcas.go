package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// TrustedCAs holds the certificate authorities HTTPS checks trust on top of
// the public ones. Like the destination policy, the Helm values seed them
// and, when editable, administrators manage them in the web.
type TrustedCAs struct {
	mu        sync.RWMutex
	pems      []string
	certs     []*x509.Certificate
	editable  bool
	updatedAt time.Time
	updatedBy string
}

// LoadTrustedCAs returns the holder for a server: with editable=true the
// stored authorities win, and the seed (Helm values) is saved on the first
// start; otherwise the seed is used as is.
func LoadTrustedCAs(ctx context.Context, st *store.Store, seed []string, editable bool, now time.Time) (*TrustedCAs, error) {
	pems, err := probes.NormalizeTrustedCAs(seed)
	if err != nil {
		return nil, fmt.Errorf("trusted certificate authorities in the configuration: %w", err)
	}
	h := &TrustedCAs{editable: editable}
	if err := h.set(pems, now, SeedPolicyActor); err != nil {
		return nil, err
	}
	if !editable {
		return h, nil
	}
	stored, err := st.GetTrustedCAs(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b, _ := json.Marshal(pems)
		ev := store.AuditEvent{ActorID: "system:helm", Action: "trusted_cas.seed", Outcome: "success",
			DetailsJSON: caAuditDetails(nil, h.certs)}
		if err := st.SaveTrustedCAs(ctx, store.StoredTrustedCAs{CertificatesJSON: string(b), UpdatedAt: now, UpdatedBy: SeedPolicyActor}, ev); err != nil {
			return nil, fmt.Errorf("seed trusted certificate authorities: %w", err)
		}
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("load trusted certificate authorities: %w", err)
	}
	var list []string
	if err := json.Unmarshal([]byte(stored.CertificatesJSON), &list); err != nil {
		return nil, fmt.Errorf("stored trusted certificate authorities are corrupt: %w", err)
	}
	if err := h.set(list, stored.UpdatedAt, stored.UpdatedBy); err != nil {
		return nil, fmt.Errorf("stored trusted certificate authorities are invalid: %w", err)
	}
	return h, nil
}

func (h *TrustedCAs) set(pems []string, at time.Time, by string) error {
	certs, err := probes.ParseTrustedCAs(pems)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pems, h.certs, h.updatedAt, h.updatedBy = append([]string{}, pems...), certs, at, by
	return nil
}

// forSpec returns the authorities to send to the probe: only runs with an
// HTTPS check use them, so other runs do not carry (nor store) them.
func (h *TrustedCAs) forSpec(spec probes.Spec) []string {
	if h == nil {
		return nil
	}
	for _, c := range spec.Checks {
		if c.Method == probes.MethodHTTPS {
			h.mu.RLock()
			defer h.mu.RUnlock()
			if len(h.pems) == 0 {
				return nil
			}
			return append([]string(nil), h.pems...)
		}
	}
	return nil
}

// CertificateView describes one trusted authority.
type CertificateView struct {
	PEM         string    `json:"pem"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprintSha256"`
	Expired     bool      `json:"expired"`
}

type trustedCAsView struct {
	Certificates []CertificateView `json:"certificates"`
	ManagedBy    string            `json:"managedBy"`
	Editable     bool              `json:"editable"`
	UpdatedAt    time.Time         `json:"updatedAt"`
	UpdatedBy    string            `json:"updatedBy"`
}

func (h *TrustedCAs) view(now time.Time) trustedCAsView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v := trustedCAsView{Certificates: []CertificateView{}, ManagedBy: "ui", Editable: h.editable, UpdatedAt: h.updatedAt, UpdatedBy: h.updatedBy}
	if !h.editable {
		v.ManagedBy = "helm"
	}
	for i, c := range h.certs {
		v.Certificates = append(v.Certificates, CertificateView{PEM: h.pems[i], Subject: c.Subject.String(), Issuer: c.Issuer.String(),
			NotBefore: c.NotBefore, NotAfter: c.NotAfter, Fingerprint: probes.Fingerprint(c), Expired: now.After(c.NotAfter)})
	}
	return v
}

// caAuditDetails lists what changed by name and fingerprint, never the PEM.
func caAuditDetails(before, after []*x509.Certificate) string {
	list := func(cs []*x509.Certificate) []map[string]string {
		out := []map[string]string{}
		for _, c := range cs {
			out = append(out, map[string]string{"subject": c.Subject.String(), "fingerprintSha256": probes.Fingerprint(c)})
		}
		return out
	}
	b, _ := json.Marshal(map[string]any{"before": list(before), "after": list(after)})
	return string(b)
}

func (s *Server) adminTrustedCAs(w http.ResponseWriter, r *http.Request) {
	if s.TrustedCAs == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "trusted certificate authorities are not available", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.TrustedCAs.view(time.Now()))
}

func (s *Server) adminSetTrustedCAs(w http.ResponseWriter, r *http.Request) {
	if s.TrustedCAs == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "trusted certificate authorities are not available", nil)
		return
	}
	if !s.TrustedCAs.editable {
		writeError(w, r, http.StatusConflict, "trusted_cas_managed_by_helm", "the trusted certificate authorities are managed in the Helm values (trustedCasManagedBy: helm)", nil)
		return
	}
	var req struct {
		Certificates []string `json:"certificates"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	pems, err := probes.NormalizeTrustedCAs(req.Certificates)
	var fe probes.FieldError
	if errors.As(err, &fe) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the certificates are not valid", []probes.FieldError{fe})
		return
	}
	certs, _ := probes.ParseTrustedCAs(pems)
	id := identity(r)
	s.TrustedCAs.mu.RLock()
	before := s.TrustedCAs.certs
	s.TrustedCAs.mu.RUnlock()
	b, _ := json.Marshal(pems)
	now := time.Now()
	ev := store.AuditEvent{ActorID: id.ID, Action: "trusted_cas.update", Outcome: "success", RequestID: RequestID(r.Context()),
		DetailsJSON: caAuditDetails(before, certs)}
	if err := s.Store.SaveTrustedCAs(r.Context(), store.StoredTrustedCAs{CertificatesJSON: string(b), UpdatedAt: now, UpdatedBy: id.Username}, ev); err != nil {
		s.Log.Error("save trusted certificate authorities failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the certificate authorities", nil)
		return
	}
	_ = s.TrustedCAs.set(pems, now, id.Username)
	s.Log.Info("trusted certificate authorities updated", "request_id", RequestID(r.Context()), "actor", id.Username, "count", len(pems))
	writeJSON(w, http.StatusOK, s.TrustedCAs.view(now))
}
