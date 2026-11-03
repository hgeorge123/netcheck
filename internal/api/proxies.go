package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// Proxies holds the HTTP proxies TCP and HTTPS checks may go through. Like
// the destination policy, the Helm values seed them and, when editable,
// administrators manage them in the web.
type Proxies struct {
	mu        sync.RWMutex
	list      []probes.Proxy
	editable  bool
	updatedAt time.Time
	updatedBy string
}

// LoadProxies returns the holder for a server: with editable=true the stored
// proxies win, and the seed (Helm values) is saved on the first start;
// otherwise the seed is used as is.
func LoadProxies(ctx context.Context, st *store.Store, seed []probes.Proxy, editable bool, now time.Time) (*Proxies, error) {
	list, err := probes.NormalizeProxies(seed)
	if err != nil {
		return nil, fmt.Errorf("proxies in the configuration: %w", err)
	}
	h := &Proxies{list: list, editable: editable, updatedAt: now, updatedBy: SeedPolicyActor}
	if !editable {
		return h, nil
	}
	stored, err := st.GetProxies(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		b, _ := json.Marshal(list)
		ev := store.AuditEvent{ActorID: "system:helm", Action: "proxies.seed", Outcome: "success", DetailsJSON: string(b)}
		if err := st.SaveProxies(ctx, store.StoredProxies{ProxiesJSON: string(b), UpdatedAt: now, UpdatedBy: SeedPolicyActor}, ev); err != nil {
			return nil, fmt.Errorf("seed proxies: %w", err)
		}
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("load proxies: %w", err)
	}
	var saved []probes.Proxy
	if err := json.Unmarshal([]byte(stored.ProxiesJSON), &saved); err != nil {
		return nil, fmt.Errorf("stored proxies are corrupt: %w", err)
	}
	if h.list, err = probes.NormalizeProxies(saved); err != nil {
		return nil, fmt.Errorf("stored proxies are invalid: %w", err)
	}
	h.updatedAt, h.updatedBy = stored.UpdatedAt, stored.UpdatedBy
	return h, nil
}

// List returns the configured proxies (none for a nil holder).
func (h *Proxies) List() []probes.Proxy {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]probes.Proxy{}, h.list...)
}

type proxiesView struct {
	Proxies   []probes.Proxy `json:"proxies"`
	ManagedBy string         `json:"managedBy"`
	Editable  bool           `json:"editable"`
	UpdatedAt time.Time      `json:"updatedAt"`
	UpdatedBy string         `json:"updatedBy"`
}

func (h *Proxies) view() proxiesView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v := proxiesView{Proxies: append([]probes.Proxy{}, h.list...), ManagedBy: "ui", Editable: h.editable, UpdatedAt: h.updatedAt, UpdatedBy: h.updatedBy}
	if !h.editable {
		v.ManagedBy = "helm"
	}
	return v
}

func (s *Server) adminProxies(w http.ResponseWriter, r *http.Request) {
	if s.Proxies == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "proxies are not available", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.Proxies.view())
}

func (s *Server) adminSetProxies(w http.ResponseWriter, r *http.Request) {
	if s.Proxies == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "proxies are not available", nil)
		return
	}
	if !s.Proxies.editable {
		writeError(w, r, http.StatusConflict, "proxies_managed_by_helm", "the proxies are managed in the Helm values (proxiesManagedBy: helm)", nil)
		return
	}
	var req struct {
		Proxies []probes.Proxy `json:"proxies"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	list, err := probes.NormalizeProxies(req.Proxies)
	var fe probes.FieldError
	if errors.As(err, &fe) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the proxies are not valid", []probes.FieldError{fe})
		return
	}
	id := identity(r)
	before := s.Proxies.List()
	b, _ := json.Marshal(list)
	details, _ := json.Marshal(map[string]any{"before": before, "after": list})
	now := time.Now()
	ev := store.AuditEvent{ActorID: id.ID, Action: "proxies.update", Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(details)}
	if err := s.Store.SaveProxies(r.Context(), store.StoredProxies{ProxiesJSON: string(b), UpdatedAt: now, UpdatedBy: id.Username}, ev); err != nil {
		s.Log.Error("save proxies failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the proxies", nil)
		return
	}
	s.Proxies.mu.Lock()
	s.Proxies.list, s.Proxies.updatedAt, s.Proxies.updatedBy = list, now, id.Username
	s.Proxies.mu.Unlock()
	s.Log.Info("proxies updated", "request_id", RequestID(r.Context()), "actor", id.Username, "count", len(list))
	writeJSON(w, http.StatusOK, s.Proxies.view())
}
