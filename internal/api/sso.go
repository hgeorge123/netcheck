package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

// providers tells the sign-in page which methods are available.
func (s *Server) providers(w http.ResponseWriter, _ *http.Request) {
	oidc := map[string]any{"enabled": s.OIDC != nil}
	if s.OIDC != nil {
		oidc["name"] = s.SSOName
	}
	writeJSON(w, http.StatusOK, map[string]any{"oidc": oidc})
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "single sign-on is not enabled", nil)
		return
	}
	if err := s.OIDC.Start(w, r); err != nil {
		s.Log.Error("sso start failed", "request_id", RequestID(r.Context()), "error", err)
		http.Redirect(w, r, "/#/?sso=unavailable", http.StatusFound)
	}
}

// oidcCallback finishes the sign-in and always lands on the UI root: never
// on a URL taken from the request, so it cannot become an open redirect.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "single sign-on is not enabled", nil)
		return
	}
	s.OIDC.ClearCookie(w)
	token, err := s.OIDC.Callback(r, s.Local.ClientIP(r), r.UserAgent(), RequestID(r.Context()))
	code := ""
	switch {
	case err == nil:
		s.Local.SetCookie(w, token)
		http.Redirect(w, r, "/#/", http.StatusFound)
		return
	case errors.Is(err, auth.ErrNoAccess):
		code = "no_access"
	case errors.Is(err, auth.ErrUsernameTaken):
		code = "username_taken"
	default:
		code = "failed"
		s.Log.Warn("sso sign-in failed", "request_id", RequestID(r.Context()), "error", err)
	}
	http.Redirect(w, r, "/#/?sso="+code, http.StatusFound)
}

// AccessRuleView is the admin representation of an access rule.
type AccessRuleView struct {
	ID                     string    `json:"id"`
	SubjectType            string    `json:"subjectType"`
	Subject                string    `json:"subject"`
	Role                   string    `json:"role"`
	AllNamespaces          bool      `json:"allNamespaces"`
	AllowNetcheckNamespace bool      `json:"allowNetcheckNamespace"`
	Namespaces             []string  `json:"namespaces"`
	UpdatedAt              time.Time `json:"updatedAt"`
	UpdatedBy              string    `json:"updatedBy"`
}

func ruleView(r store.AccessRule) AccessRuleView {
	return AccessRuleView{ID: r.ID, SubjectType: r.SubjectType, Subject: r.Subject, Role: r.Role, AllNamespaces: r.AllNamespaces,
		AllowNetcheckNamespace: r.AllowNetcheckNamespace, Namespaces: r.Namespaces, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
}

func (s *Server) adminAccessRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Store.ListAccessRules(r.Context())
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	items := make([]AccessRuleView, len(rules))
	for i, x := range rules {
		items[i] = ruleView(x)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "ssoEnabled": s.OIDC != nil})
}

func (s *Server) adminSaveAccessRule(w http.ResponseWriter, r *http.Request) {
	var in auth.AccessRuleInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	rule, err := s.Local.SaveAccessRule(r.Context(), identity(r), r.PathValue("id"), in, RequestID(r.Context()))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	status := http.StatusOK
	if r.PathValue("id") == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, ruleView(rule))
}

func (s *Server) adminDeleteAccessRule(w http.ResponseWriter, r *http.Request) {
	if err := s.Local.DeleteAccessRule(r.Context(), identity(r), r.PathValue("id"), RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
