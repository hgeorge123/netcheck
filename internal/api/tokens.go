package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

// tokenAllowed is the scope of API tokens: run tests and read them, with the
// profile, namespaces and catalog needed to do so. Everything else (users,
// tokens, policies, sign-out) requires a browser session.
func tokenAllowed(r *http.Request) bool {
	p := r.URL.Path
	switch r.Method {
	case http.MethodGet:
		return p == "/api/v1/me" || p == "/api/v1/namespaces" || p == "/api/v1/probes/catalog" || p == "/api/v1/runs" ||
			(strings.HasPrefix(p, "/api/v1/runs/") && !strings.Contains(strings.TrimPrefix(p, "/api/v1/runs/"), "/"))
	case http.MethodPost:
		return p == "/api/v1/runs"
	}
	return false
}

// TokenView describes a token (never its secret).
type TokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Owner      string     `json:"owner"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

func tokenView(t store.APIToken) TokenView {
	return TokenView{ID: t.ID, Name: t.Name, Prefix: t.Prefix, Owner: t.Username, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt}
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, userID string) {
	list, err := s.Store.ListAPITokens(r.Context(), userID)
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	items := make([]TokenView, len(list))
	for i, t := range list {
		items[i] = tokenView(t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) myTokens(w http.ResponseWriter, r *http.Request) { s.listTokens(w, r, identity(r).ID) }

func (s *Server) adminTokens(w http.ResponseWriter, r *http.Request) { s.listTokens(w, r, "") }

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, auth.PermTokensCreate) {
		return
	}
	var in auth.TokenInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	raw, tk, err := s.Local.CreateToken(r.Context(), identity(r), in, RequestID(r.Context()))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	// The secret is returned this time only.
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "item": tokenView(tk)})
}

func (s *Server) revokeMyToken(w http.ResponseWriter, r *http.Request) {
	s.revokeToken(w, r, false)
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	s.revokeToken(w, r, true)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, all bool) {
	if err := s.Local.RevokeToken(r.Context(), identity(r), r.PathValue("id"), all, RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
