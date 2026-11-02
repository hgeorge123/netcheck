package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

// NamespaceAdmin backs Administration > Namespaces: web exclusions on top of
// the Helm and system ones. The web can only add exclusions.
type NamespaceAdmin struct {
	// All lists every namespace in scope (live namespaces in "all" mode, the
	// configured list in "list" mode), including excluded ones.
	All func(ctx context.Context) ([]string, error)
	// Web is the filter applied to the available namespaces.
	Web *auth.WebExclusions
	// HelmExcluded is namespaceScope.exclude; System are always excluded.
	HelmExcluded []string
	System       []string
}

// Namespace statuses shown in the administration page.
const (
	nsAvailable = "available"
	nsWeb       = "excluded_web"
	nsHelm      = "excluded_helm"
	nsSystem    = "system"
	nsNetCheck  = "netcheck"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// NamespaceView is one row of the administration page.
type NamespaceView struct {
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Exists     bool       `json:"exists"`
	Reason     string     `json:"reason,omitempty"`
	ExcludedBy string     `json:"excludedBy,omitempty"`
	ExcludedAt *time.Time `json:"excludedAt,omitempty"`
}

func (s *Server) namespaceStatus(name string) string {
	switch {
	case slices.Contains(s.NSAdmin.System, name):
		return nsSystem
	case name == s.Authz.OwnNamespace:
		return nsNetCheck
	case slices.Contains(s.NSAdmin.HelmExcluded, name):
		return nsHelm
	case s.NSAdmin.Web.Excluded(name):
		return nsWeb
	}
	return nsAvailable
}

func (s *Server) adminNamespaceExclusions(w http.ResponseWriter, r *http.Request) {
	if s.NSAdmin == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "namespace administration not configured", nil)
		return
	}
	all, err := s.NSAdmin.All(r.Context())
	if err != nil {
		s.Log.Error("namespace listing failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "namespaces_unavailable", "could not list the cluster namespaces", nil)
		return
	}
	web, err := s.Store.ListNamespaceExclusions(r.Context())
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	byName := map[string]store.NamespaceExclusion{}
	for _, e := range web {
		byName[e.Name] = e
	}
	names := slices.Clone(all)
	for _, e := range web { // excluded but not (or no longer) present
		if !slices.Contains(names, e.Name) {
			names = append(names, e.Name)
		}
	}
	slices.Sort(names)
	items := make([]NamespaceView, 0, len(names))
	for _, n := range names {
		v := NamespaceView{Name: n, Status: s.namespaceStatus(n), Exists: slices.Contains(all, n)}
		if e, ok := byName[n]; ok {
			at := e.CreatedAt
			v.Reason, v.ExcludedBy, v.ExcludedAt = e.Reason, e.CreatedBy, &at
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "mode": s.ScopeMode, "helmExcluded": append([]string{}, s.NSAdmin.HelmExcluded...)})
}

func (s *Server) adminExcludeNamespace(w http.ResponseWriter, r *http.Request) {
	if s.NSAdmin == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "namespace administration not configured", nil)
		return
	}
	var req struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	req.Name, req.Reason = strings.TrimSpace(req.Name), strings.TrimSpace(req.Reason)
	if !dnsLabel.MatchString(req.Name) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "invalid namespace name",
			[]map[string]string{{"field": "name", "code": "invalid_namespace", "message": "lowercase letters, digits and '-', at most 63 characters"}})
		return
	}
	if len(req.Reason) > 200 || strings.ContainsFunc(req.Reason, unicode.IsControl) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "invalid reason",
			[]map[string]string{{"field": "reason", "code": "invalid_reason", "message": "at most 200 printable characters"}})
		return
	}
	if st := s.namespaceStatus(req.Name); st != nsAvailable {
		writeError(w, r, http.StatusConflict, "already_excluded", "the namespace is already excluded ("+st+")", nil)
		return
	}
	id := identity(r)
	details, _ := json.Marshal(map[string]string{"namespace": req.Name, "reason": req.Reason})
	ev := store.AuditEvent{ActorID: id.ID, Action: "namespace.exclude", Namespace: req.Name, Outcome: "success",
		RequestID: RequestID(r.Context()), DetailsJSON: string(details)}
	err := s.Store.AddNamespaceExclusion(r.Context(), store.NamespaceExclusion{Name: req.Name, Reason: req.Reason, CreatedAt: time.Now(), CreatedBy: id.Username}, ev)
	if errors.Is(err, store.ErrAlreadyExists) {
		writeError(w, r, http.StatusConflict, "already_excluded", "the namespace is already excluded", nil)
		return
	}
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	if err := s.reloadExclusions(r.Context()); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	s.Log.Info("namespace excluded in the web", "request_id", RequestID(r.Context()), "namespace", req.Name, "actor", id.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminIncludeNamespace(w http.ResponseWriter, r *http.Request) {
	if s.NSAdmin == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "namespace administration not configured", nil)
		return
	}
	name := r.PathValue("name")
	switch st := s.namespaceStatus(name); st {
	case nsWeb:
	case nsAvailable:
		writeError(w, r, http.StatusNotFound, "not_found", "the namespace is not excluded in the web", nil)
		return
	default:
		writeError(w, r, http.StatusConflict, "managed_by_helm", "this exclusion comes from Helm or the system and cannot be removed from the web ("+st+")", nil)
		return
	}
	id := identity(r)
	ev := store.AuditEvent{ActorID: id.ID, Action: "namespace.include", Namespace: name, Outcome: "success", RequestID: RequestID(r.Context())}
	if err := s.Store.DeleteNamespaceExclusion(r.Context(), name, ev); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	if err := s.reloadExclusions(r.Context()); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	s.Log.Info("namespace included again in the web", "request_id", RequestID(r.Context()), "namespace", name, "actor", id.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reloadExclusions(ctx context.Context) error {
	list, err := s.Store.ListNamespaceExclusions(ctx)
	if err != nil {
		return err
	}
	names := make([]string, len(list))
	for i, e := range list {
		names[i] = e.Name
	}
	s.NSAdmin.Web.Set(names)
	return nil
}
