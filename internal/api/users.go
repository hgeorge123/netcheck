package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

// UserView is the admin representation of an account (never the hash).
type UserView struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"displayName"`
	Role               string     `json:"role"`
	AllNamespaces      bool       `json:"allNamespaces"`
	Namespaces         []string   `json:"namespaces"`
	Disabled           bool       `json:"disabled"`
	Locked             bool       `json:"locked"`
	LockedUntil        *time.Time `json:"lockedUntil,omitempty"`
	MustChangePassword bool       `json:"mustChangePassword"`
	CreatedAt          time.Time  `json:"createdAt"`
	LastLoginAt        *time.Time `json:"lastLoginAt,omitempty"`
	PasswordChangedAt  time.Time  `json:"passwordChangedAt"`
	Language           string     `json:"language"`

	AllowNetcheckNamespace bool `json:"allowNetcheckNamespace"`
}

func userView(u store.User, now time.Time) UserView {
	ns := u.Namespaces
	if ns == nil {
		ns = []string{}
	}
	locked := u.LockedUntil != nil && now.Before(*u.LockedUntil)
	v := UserView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, AllNamespaces: u.AllNamespaces,
		Namespaces: ns, Disabled: u.Disabled, Locked: locked, MustChangePassword: u.MustChangePassword, CreatedAt: u.CreatedAt,
		LastLoginAt: u.LastLoginAt, PasswordChangedAt: u.PasswordChangedAt, Language: u.Language, AllowNetcheckNamespace: u.AllowNetcheckNamespace}
	if locked {
		v.LockedUntil = u.LockedUntil
	}
	return v
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !identity(r).IsAdmin() {
			writeError(w, r, http.StatusForbidden, "admin_required", "this operation requires the admin role", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeUserError maps service errors to API responses.
func (s *Server) writeUserError(w http.ResponseWriter, r *http.Request, err error) {
	var ie auth.InputError
	switch {
	case errors.As(err, &ie):
		writeError(w, r, http.StatusBadRequest, "validation_failed", ie.Message, []map[string]string{{"field": ie.Field, "code": ie.Code, "message": ie.Message}})
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "user not found", nil)
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, r, http.StatusConflict, "last_admin", "the system cannot be left without an active administrator", nil)
	case errors.Is(err, auth.ErrForbiddenSelf):
		writeError(w, r, http.StatusConflict, "self_operation", "you cannot delete, disable or demote your own account", nil)
	default:
		s.Log.Error("user operation failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	token, id, err := s.Local.Login(r.Context(), req.Username, req.Password, s.Local.ClientIP(r), r.UserAgent(), RequestID(r.Context()))
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts; wait a minute", nil)
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials",
			"incorrect username or password (the account is locked temporarily after several failures)", nil)
		return
	case err != nil:
		s.Log.Error("login failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
		return
	}
	s.Local.SetCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"id": id.ID, "username": id.Username, "role": id.Role, "mustChangePassword": id.MustChangePassword})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.Local.Logout(r.Context(), identity(r), RequestID(r.Context())); err != nil {
		s.Log.Error("logout failed", "request_id", RequestID(r.Context()), "error", err)
	}
	s.Local.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	if err := s.Local.ChangeOwnPassword(r.Context(), identity(r), req.CurrentPassword, req.NewPassword, RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	now := time.Now()
	items := make([]UserView, len(users))
	for i, u := range users {
		items[i] = userView(u, now)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userView(u, time.Now()))
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var in auth.UserInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	u, err := s.Local.CreateUser(r.Context(), identity(r), in, RequestID(r.Context()))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, userView(u, time.Now()))
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var in auth.UserInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	if in.Password != "" || in.Username != "" {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the username cannot be changed and passwords are reset separately", nil)
		return
	}
	u, err := s.Local.UpdateUser(r.Context(), identity(r), r.PathValue("id"), in, RequestID(r.Context()))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userView(u, time.Now()))
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.Local.DeleteUser(r.Context(), identity(r), r.PathValue("id"), RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	if err := s.Local.ResetPassword(r.Context(), identity(r), r.PathValue("id"), req.Password, RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminUnlock(w http.ResponseWriter, r *http.Request) {
	if err := s.Local.Unlock(r.Context(), identity(r), r.PathValue("id"), RequestID(r.Context())); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminNamespaces lists namespaces that can be assigned to users.
func (s *Server) adminNamespaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.Local.Namespaces.Available(r.Context())
	if err != nil {
		s.Log.Error("namespace listing failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "namespaces_unavailable", "could not list the cluster namespaces", nil)
		return
	}
	if list == nil {
		list = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "mode": s.ScopeMode, "netcheckNamespace": s.Authz.OwnNamespace})
}
