package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// RoleView describes a role. For built-in roles, permissions are the ones
// defined in the code.
type RoleView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Builtin     bool      `json:"builtin"`
	Users       int       `json:"users"`
	Rules       int       `json:"rules"`
	UpdatedAt   time.Time `json:"updatedAt"`
	UpdatedBy   string    `json:"updatedBy"`
}

type roleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) roleView(r *http.Request, role store.Role) RoleView {
	v := RoleView{ID: role.ID, Name: role.Name, Description: role.Description, Permissions: s.Authz.Roles.Permissions(role.ID),
		Builtin: role.Builtin, UpdatedAt: role.UpdatedAt, UpdatedBy: role.UpdatedBy}
	if v.Permissions == nil {
		v.Permissions = []string{}
	}
	if !role.Builtin {
		v.Users, v.Rules, _ = s.Store.RoleUsage(r.Context(), role.ID)
	}
	return v
}

func (s *Server) adminRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.Store.ListRoles(r.Context())
	if err != nil {
		s.Log.Error("list roles failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not list the roles", nil)
		return
	}
	items := make([]RoleView, len(roles))
	for i, role := range roles {
		items[i] = s.roleView(r, role)
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": items, "permissions": auth.AllPermissions()})
}

// validRole normalises a role input: a printable name, a short description
// and known permissions, in display order.
func validRole(in roleInput) (roleInput, *probes.FieldError) {
	printable := func(s string) bool {
		return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
	}
	in.Name, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 64 || !printable(in.Name) {
		return in, &probes.FieldError{Field: "name", Code: "role_name_invalid", Message: "give the role a name of 1-64 printable characters"}
	}
	if utf8.RuneCountInString(in.Description) > 256 || !printable(in.Description) {
		return in, &probes.FieldError{Field: "description", Code: "role_description_invalid", Message: "the description cannot exceed 256 printable characters"}
	}
	all := auth.AllPermissions()
	perms := []string{}
	for _, p := range in.Permissions {
		if !slices.Contains(all, p) {
			return in, &probes.FieldError{Field: "permissions", Code: "unknown_permission", Message: "unknown permission " + p}
		}
	}
	for _, p := range all {
		if slices.Contains(in.Permissions, p) {
			perms = append(perms, p)
		}
	}
	in.Permissions = perms
	return in, nil
}

func (s *Server) adminCreateRole(w http.ResponseWriter, r *http.Request) { s.saveRole(w, r, "") }
func (s *Server) adminUpdateRole(w http.ResponseWriter, r *http.Request) {
	s.saveRole(w, r, r.PathValue("id"))
}

func (s *Server) saveRole(w http.ResponseWriter, r *http.Request, id string) {
	var in roleInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	in, fe := validRole(in)
	if fe != nil {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the role is not valid", []probes.FieldError{*fe})
		return
	}
	now, actor := time.Now(), identity(r)
	role := store.Role{ID: id, Name: in.Name, Description: in.Description, Permissions: in.Permissions, CreatedAt: now, UpdatedAt: now, UpdatedBy: actor.Username}
	action, status := "role.update", http.StatusOK
	if id == "" {
		role.ID, action, status = "o"+newID(12), "role.create", http.StatusCreated
	} else {
		prev, err := s.Store.GetRole(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "not_found", "role not found", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal", "could not read the role", nil)
			return
		}
		role.CreatedAt = prev.CreatedAt
	}
	b, _ := json.Marshal(map[string]any{"roleId": role.ID, "name": role.Name, "permissions": role.Permissions})
	ev := store.AuditEvent{ActorID: actor.ID, Action: action, Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(b)}
	switch err := s.Store.SaveRole(r.Context(), role, ev); {
	case errors.Is(err, store.ErrBuiltinRole):
		writeError(w, r, http.StatusConflict, "builtin_role", "built-in roles cannot be changed", nil)
		return
	case errors.Is(err, store.ErrRoleExists):
		writeError(w, r, http.StatusConflict, "role_exists", "there is already a role with that name",
			[]probes.FieldError{{Field: "name", Code: "role_exists", Message: "there is already a role with that name"}})
		return
	case err != nil:
		s.Log.Error("save role failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the role", nil)
		return
	}
	s.reloadRoles(r)
	saved, _ := s.Store.GetRole(r.Context(), role.ID)
	s.Log.Info("role saved", "request_id", RequestID(r.Context()), "actor", actor.Username, "role", role.ID, "name", role.Name)
	writeJSON(w, status, s.roleView(r, saved))
}

func (s *Server) adminDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, actor := r.PathValue("id"), identity(r)
	b, _ := json.Marshal(map[string]any{"roleId": id})
	ev := store.AuditEvent{ActorID: actor.ID, Action: "role.delete", Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(b)}
	switch err := s.Store.DeleteRole(r.Context(), id, ev); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "role not found", nil)
		return
	case errors.Is(err, store.ErrBuiltinRole):
		writeError(w, r, http.StatusConflict, "builtin_role", "built-in roles cannot be deleted", nil)
		return
	case errors.Is(err, store.ErrRoleInUse):
		writeError(w, r, http.StatusConflict, "role_in_use", "the role is still given to users or access rules: change them first", nil)
		return
	case err != nil:
		s.Log.Error("delete role failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not delete the role", nil)
		return
	}
	s.reloadRoles(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reloadRoles(r *http.Request) {
	if err := s.Authz.Roles.Reload(r.Context(), s.Store); err != nil {
		s.Log.Error("reload roles failed", "request_id", RequestID(r.Context()), "error", err)
	}
}

// adminUserPermissions shows what a user can do and where it comes from:
// its grants (account or access rules), the namespaces with the checks
// allowed in each, and the permissions that do not depend on a namespace.
func (s *Server) adminUserPermissions(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "not_found", "user not found", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal", "could not read the user", nil)
		return
	}
	id := s.Local.IdentityFor(r.Context(), u)
	namespaces, err := s.Authz.Grants(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "namespaces_unavailable", "could not list the cluster namespaces", nil)
		return
	}
	type grantView struct {
		auth.Grant
		RoleName string `json:"roleName"`
	}
	grants := []grantView{}
	for _, g := range id.EffectiveGrants() {
		if g.Namespaces == nil {
			g.Namespaces = []string{}
		}
		grants = append(grants, grantView{Grant: g, RoleName: s.Authz.Roles.Name(g.Role)})
	}
	// Check types switched off for everybody are not available anywhere.
	for i := range namespaces {
		namespaces[i].Checks = slices.DeleteFunc(namespaces[i].Checks, func(m string) bool { return !s.CheckTypes.Enabled(m) })
		namespaces[i].FirewallMode = namespaces[i].FirewallMode && s.CheckTypes.Enabled(probes.CheckTypeFirewall)
	}
	writeJSON(w, http.StatusOK, map[string]any{"admin": id.IsAdmin(), "grants": grants, "namespaces": namespaces, "permissions": s.Authz.Permissions(id)})
}
