package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// maxPolicyEntries bounds each list of the destination policy.
const maxPolicyEntries = 200

// SeedPolicyActor marks a policy copied from the Helm values on first start.
const SeedPolicyActor = "helm (initial values)"

// DestinationPolicies holds the destination policy used for new runs. The
// editable part (base) comes from the database or the configuration; the
// platform denies (metadata, API server...) come only from the configuration
// and are always added on top, so the web UI can never remove them.
type DestinationPolicies struct {
	mu        sync.RWMutex
	base      probes.DestinationPolicy
	platform  []string
	editable  bool
	updatedAt time.Time
	updatedBy string
	// API server addresses detected in the cluster (exact IPs). Until the
	// first detection the fallback ranges are denied instead (fail closed).
	apiServer         []string
	apiServerFallback []string
	apiServerDetected bool
}

// SetAPIServerFallback sets the ranges denied while the exact API server
// addresses are unknown (networkPolicy.apiServer.cidrs in the chart).
func (h *DestinationPolicies) SetAPIServerFallback(cidrs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.apiServerFallback = append([]string(nil), cidrs...)
}

// SetAPIServerAddresses replaces the detected API server addresses. An empty
// list is ignored: the last known addresses (or the fallback) stay denied.
// It reports whether the denied addresses changed.
func (h *DestinationPolicies) SetAPIServerAddresses(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.apiServerDetected && slices.Equal(h.apiServer, addrs) {
		return false
	}
	h.apiServer, h.apiServerDetected = append([]string(nil), addrs...), true
	return true
}

// platformDenies is the configured platform denies plus the API server:
// the detected addresses, or the fallback ranges until they are known.
func (h *DestinationPolicies) platformDenies() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := append([]string{}, h.platform...)
	if h.apiServerDetected {
		return append(out, h.apiServer...)
	}
	return append(out, h.apiServerFallback...)
}

// NewDestinationPolicies builds a holder. editable=false means the policy is
// managed in Helm and the web UI is read-only.
func NewDestinationPolicies(base probes.DestinationPolicy, platform []string, editable bool) *DestinationPolicies {
	return &DestinationPolicies{base: normalizePolicy(base), platform: append([]string(nil), platform...), editable: editable}
}

// LoadDestinationPolicies returns the holder for a server: with editable=true
// the policy stored in the database wins, and the seed (Helm values) is saved
// on the first start; otherwise the seed is used as is.
func LoadDestinationPolicies(ctx context.Context, st *store.Store, seed probes.DestinationPolicy, platform []string, editable bool, now time.Time) (*DestinationPolicies, error) {
	h := NewDestinationPolicies(seed, platform, editable)
	h.updatedBy, h.updatedAt = SeedPolicyActor, now
	if !editable {
		return h, nil
	}
	stored, err := st.GetDestinationPolicy(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b, _ := json.Marshal(h.base)
		ev := store.AuditEvent{ActorID: "system:helm", Action: "policy.seed", Outcome: "success", DetailsJSON: string(b)}
		if err := st.SaveDestinationPolicy(ctx, store.StoredPolicy{PolicyJSON: string(b), UpdatedAt: now, UpdatedBy: SeedPolicyActor}, ev); err != nil {
			return nil, fmt.Errorf("seed destination policy: %w", err)
		}
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("load destination policy: %w", err)
	}
	var p probes.DestinationPolicy
	if err := json.Unmarshal([]byte(stored.PolicyJSON), &p); err != nil {
		return nil, fmt.Errorf("stored destination policy is corrupt: %w", err)
	}
	if _, err := p.WithDenies(platform...).Compile(); err != nil {
		return nil, fmt.Errorf("stored destination policy is invalid: %w", err)
	}
	h.base, h.updatedAt, h.updatedBy = normalizePolicy(p), stored.UpdatedAt, stored.UpdatedBy
	return h, nil
}

// Effective is the policy applied to new runs (base + platform denies).
func (h *DestinationPolicies) Effective() probes.DestinationPolicy {
	denies := h.platformDenies()
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.base.WithDenies(denies...)
}

func (h *DestinationPolicies) snapshot() (probes.DestinationPolicy, time.Time, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.base, h.updatedAt, h.updatedBy
}

func (h *DestinationPolicies) set(p probes.DestinationPolicy, at time.Time, by string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.base, h.updatedAt, h.updatedBy = p, at, by
}

// normalizePolicy trims entries, drops empty ones and never returns nil lists.
func normalizePolicy(p probes.DestinationPolicy) probes.DestinationPolicy {
	clean := func(in []string) []string {
		out := []string{}
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	ports := []probes.PortRange{}
	ports = append(ports, p.AllowPorts...)
	return probes.DestinationPolicy{AllowCIDRs: clean(p.AllowCIDRs), DenyCIDRs: clean(p.DenyCIDRs),
		AllowHostnameSuffixes: clean(p.AllowHostnameSuffixes), AllowPorts: ports}
}

// policyFieldError maps a Compile error ("allowCidrs: ...") to a field error.
func policyFieldError(err error) probes.FieldError {
	msg := err.Error()
	field, _, _ := strings.Cut(msg, ":")
	code := map[string]string{"allowCidrs": "invalid_cidr", "denyCidrs": "invalid_cidr",
		"allowHostnameSuffixes": "invalid_suffix", "allowPorts": "invalid_port_range"}[field]
	if code == "" {
		field, code = "policy", "invalid"
	}
	return probes.FieldError{Field: field, Code: code, Message: msg}
}

type policyView struct {
	Policy                      probes.DestinationPolicy `json:"policy"`
	PlatformDenies              []string                 `json:"platformDenies"`
	ProtectPlatformDestinations bool                     `json:"protectPlatformDestinations"`
	ManagedBy                   string                   `json:"managedBy"`
	Editable                    bool                     `json:"editable"`
	UpdatedAt                   time.Time                `json:"updatedAt"`
	UpdatedBy                   string                   `json:"updatedBy"`
}

func (s *Server) policyView() policyView {
	base, at, by := s.Policies.snapshot()
	managed := "ui"
	if !s.Policies.editable {
		managed = "helm"
	}
	platform := s.Policies.platformDenies()
	return policyView{Policy: base, PlatformDenies: platform, ProtectPlatformDestinations: len(platform) > 0, ManagedBy: managed,
		Editable: s.Policies.editable, UpdatedAt: at, UpdatedBy: by}
}

func (s *Server) adminPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.policyView())
}

func (s *Server) adminSetPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.Policies.editable {
		writeError(w, r, http.StatusConflict, "policy_managed_by_helm", "the destination policy is managed in the Helm values (destinationsManagedBy: helm)", nil)
		return
	}
	var req probes.DestinationPolicy
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	p := normalizePolicy(req)
	for field, n := range map[string]int{"allowCidrs": len(p.AllowCIDRs), "denyCidrs": len(p.DenyCIDRs),
		"allowHostnameSuffixes": len(p.AllowHostnameSuffixes), "allowPorts": len(p.AllowPorts)} {
		if n > maxPolicyEntries {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "the policy is not valid",
				[]probes.FieldError{{Field: field, Code: "too_many", Message: fmt.Sprintf("at most %d entries", maxPolicyEntries)}})
			return
		}
	}
	if _, err := p.WithDenies(s.Policies.platformDenies()...).Compile(); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the policy is not valid", []probes.FieldError{policyFieldError(err)})
		return
	}
	id := identity(r)
	before, _, _ := s.Policies.snapshot()
	b, _ := json.Marshal(p)
	details, _ := json.Marshal(map[string]any{"before": before, "after": p})
	now := time.Now()
	ev := store.AuditEvent{ActorID: id.ID, Action: "policy.update", Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(details)}
	if err := s.Store.SaveDestinationPolicy(r.Context(), store.StoredPolicy{PolicyJSON: string(b), UpdatedAt: now, UpdatedBy: id.Username}, ev); err != nil {
		s.Log.Error("save destination policy failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the policy", nil)
		return
	}
	s.Policies.set(p, now, id.Username)
	s.Log.Info("destination policy updated", "request_id", RequestID(r.Context()), "actor", id.Username)
	writeJSON(w, http.StatusOK, s.policyView())
}

// adminCheckDestination evaluates a destination against the current policy
// without sending any traffic. Hostnames are only checked by suffix: their
// resolved IPs are checked again inside the probe.
func (s *Server) adminCheckDestination(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	target, err := probes.ParseTarget(req.Target)
	var fe probes.FieldError
	if errors.As(err, &fe) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the destination is not valid", []probes.FieldError{fe})
		return
	}
	c, err := s.Policies.Effective().Compile()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal", "invalid policy", nil)
		return
	}
	reason := ""
	if err := c.CheckHost(target); err != nil {
		reason = deniedReason(err)
	} else if req.Port != 0 {
		if err := c.CheckPort(req.Port); err != nil {
			reason = deniedReason(err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": reason == "", "reason": reason, "isIp": target.IsIP})
}

func deniedReason(err error) string {
	var de *probes.DeniedError
	if errors.As(err, &de) {
		return de.Reason
	}
	return err.Error()
}
