package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// CheckTypes holds the check types administrators switched off for everybody
// (administrators included). Like the destination policy, the Helm values
// seed the setting and, when editable, administrators manage it in the web.
// A nil holder allows every type.
type CheckTypes struct {
	mu        sync.RWMutex
	disabled  []string
	editable  bool
	updatedAt time.Time
	updatedBy string
}

// LoadCheckTypes returns the holder for a server: with editable=true the
// stored setting wins, and the seed (Helm values) is saved on the first
// start; otherwise the seed is used as is.
func LoadCheckTypes(ctx context.Context, st *store.Store, seed []string, editable bool, now time.Time) (*CheckTypes, error) {
	disabled, err := probes.NormalizeDisabledChecks(seed)
	if err != nil {
		return nil, fmt.Errorf("checkTypes in the configuration: %w", err)
	}
	h := &CheckTypes{editable: editable}
	h.set(disabled, now, SeedPolicyActor)
	if !editable {
		return h, nil
	}
	stored, err := st.GetCheckTypes(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b, _ := json.Marshal(disabled)
		ev := store.AuditEvent{ActorID: "system:helm", Action: "check_types.seed", Outcome: "success", DetailsJSON: checkTypesAudit(nil, disabled)}
		if err := st.SaveCheckTypes(ctx, store.StoredCheckTypes{DisabledJSON: string(b), UpdatedAt: now, UpdatedBy: SeedPolicyActor}, ev); err != nil {
			return nil, fmt.Errorf("seed check types: %w", err)
		}
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("load check types: %w", err)
	}
	var list []string
	if err := json.Unmarshal([]byte(stored.DisabledJSON), &list); err != nil {
		return nil, fmt.Errorf("stored check types are corrupt: %w", err)
	}
	// Unknown names (a type removed in a later version) are dropped, never
	// fatal: they cannot enable anything.
	known := []string{}
	for _, t := range list {
		if slices.Contains(probes.CheckTypes(), t) {
			known = append(known, t)
		}
	}
	norm, _ := probes.NormalizeDisabledChecks(known)
	h.set(norm, stored.UpdatedAt, stored.UpdatedBy)
	return h, nil
}

func (h *CheckTypes) set(disabled []string, at time.Time, by string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disabled, h.updatedAt, h.updatedBy = append([]string{}, disabled...), at, by
}

// Enabled reports whether a check type (a method, or "firewall") may be used.
func (h *CheckTypes) Enabled(t string) bool {
	if h == nil {
		return true
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return !slices.Contains(h.disabled, t)
}

// Check returns one error per disabled part of a run request: the firewall
// ticket mode and every disabled check.
func (h *CheckTypes) Check(req probes.RunRequest) []probes.FieldError {
	var errs []probes.FieldError
	if req.Mode == probes.ModeFirewall && !h.Enabled(probes.CheckTypeFirewall) {
		errs = append(errs, probes.FieldError{Field: "mode", Code: "check_type_disabled", Message: "the firewall ticket mode is disabled by an administrator"})
	}
	for i, c := range req.Checks {
		if !h.Enabled(string(c.Method)) {
			errs = append(errs, probes.FieldError{Field: fmt.Sprintf("checks[%d]", i), Code: "check_type_disabled",
				Message: fmt.Sprintf("the %s check is disabled by an administrator", c.Method)})
		}
	}
	return errs
}

// catalog returns the methods users may choose.
func (h *CheckTypes) catalog() []probes.CatalogEntry {
	out := []probes.CatalogEntry{}
	for _, e := range probes.Catalog {
		if h.Enabled(string(e.Method)) {
			out = append(out, e)
		}
	}
	return out
}

// CheckTypeView describes one check type for administrators.
type CheckTypeView struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type checkTypesView struct {
	Types     []CheckTypeView `json:"types"`
	ManagedBy string          `json:"managedBy"`
	Editable  bool            `json:"editable"`
	UpdatedAt time.Time       `json:"updatedAt"`
	UpdatedBy string          `json:"updatedBy"`
}

func (h *CheckTypes) view() checkTypesView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v := checkTypesView{Types: []CheckTypeView{}, ManagedBy: "ui", Editable: h.editable, UpdatedAt: h.updatedAt, UpdatedBy: h.updatedBy}
	if !h.editable {
		v.ManagedBy = "helm"
	}
	for _, t := range probes.CheckTypes() {
		v.Types = append(v.Types, CheckTypeView{Type: t, Enabled: !slices.Contains(h.disabled, t)})
	}
	return v
}

// checkTypesAudit records what was switched off and on.
func checkTypesAudit(before, after []string) string {
	b, _ := json.Marshal(map[string]any{"disabledBefore": nonNilList(before), "disabledAfter": nonNilList(after)})
	return string(b)
}

func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) adminCheckTypes(w http.ResponseWriter, r *http.Request) {
	if s.CheckTypes == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "check types are not available", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.CheckTypes.view())
}

func (s *Server) adminSetCheckTypes(w http.ResponseWriter, r *http.Request) {
	if s.CheckTypes == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "check types are not available", nil)
		return
	}
	if !s.CheckTypes.editable {
		writeError(w, r, http.StatusConflict, "check_types_managed_by_helm", "the check types are managed in the Helm values (checkTypesManagedBy: helm)", nil)
		return
	}
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	disabled, err := probes.NormalizeDisabledChecks(req.Disabled)
	var fe probes.FieldError
	if errors.As(err, &fe) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the check types are not valid", []probes.FieldError{fe})
		return
	}
	// At least one check must stay available, or nobody could test anything.
	if !slices.ContainsFunc(probes.Catalog, func(e probes.CatalogEntry) bool { return !slices.Contains(disabled, string(e.Method)) }) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "at least one check type must stay enabled",
			[]probes.FieldError{{Field: "disabled", Code: "all_checks_disabled", Message: "at least one check type must stay enabled"}})
		return
	}
	id := identity(r)
	s.CheckTypes.mu.RLock()
	before := append([]string{}, s.CheckTypes.disabled...)
	s.CheckTypes.mu.RUnlock()
	b, _ := json.Marshal(disabled)
	now := time.Now()
	ev := store.AuditEvent{ActorID: id.ID, Action: "check_types.update", Outcome: "success", RequestID: RequestID(r.Context()),
		DetailsJSON: checkTypesAudit(before, disabled)}
	if err := s.Store.SaveCheckTypes(r.Context(), store.StoredCheckTypes{DisabledJSON: string(b), UpdatedAt: now, UpdatedBy: id.Username}, ev); err != nil {
		s.Log.Error("save check types failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the check types", nil)
		return
	}
	s.CheckTypes.set(disabled, now, id.Username)
	s.Log.Info("check types updated", "request_id", RequestID(r.Context()), "actor", id.Username, "disabled", disabled)
	writeJSON(w, http.StatusOK, s.CheckTypes.view())
}
