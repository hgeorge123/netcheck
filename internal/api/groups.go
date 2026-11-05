package api

import (
	"context"
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

// GroupView describes a local group with its members.
type GroupView struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	Description            string    `json:"description"`
	Role                   string    `json:"role"`
	RoleName               string    `json:"roleName"`
	AllNamespaces          bool      `json:"allNamespaces"`
	AllowNetcheckNamespace bool      `json:"allowNetcheckNamespace"`
	Namespaces             []string  `json:"namespaces"`
	Members                []string  `json:"members"`
	UpdatedAt              time.Time `json:"updatedAt"`
	UpdatedBy              string    `json:"updatedBy"`
}

type groupInput struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	Role                   string   `json:"role"`
	AllNamespaces          bool     `json:"allNamespaces"`
	AllowNetcheckNamespace bool     `json:"allowNetcheckNamespace"`
	Namespaces             []string `json:"namespaces"`
	// Members are user ids.
	Members []string `json:"members"`
}

func (s *Server) groupView(g store.LocalGroup) GroupView {
	return GroupView{ID: g.ID, Name: g.Name, Description: g.Description, Role: g.Role, RoleName: s.Authz.Roles.Name(g.Role),
		AllNamespaces: g.AllNamespaces, AllowNetcheckNamespace: g.AllowNetcheckNamespace, Namespaces: g.Namespaces, Members: g.Members,
		UpdatedAt: g.UpdatedAt, UpdatedBy: g.UpdatedBy}
}

func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Store.ListGroups(r.Context())
	if err != nil {
		s.Log.Error("list groups failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not list the groups", nil)
		return
	}
	items := make([]GroupView, len(groups))
	for i, g := range groups {
		items[i] = s.groupView(g)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateGroup(w http.ResponseWriter, r *http.Request) { s.saveGroup(w, r, "") }
func (s *Server) adminUpdateGroup(w http.ResponseWriter, r *http.Request) {
	s.saveGroup(w, r, r.PathValue("id"))
}

func groupFieldError(w http.ResponseWriter, r *http.Request, field, code, msg string) {
	writeError(w, r, http.StatusBadRequest, "validation_failed", msg, []probes.FieldError{{Field: field, Code: code, Message: msg}})
}

func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request, id string) {
	var in groupInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	printable := func(v string) bool {
		return !strings.ContainsFunc(v, func(c rune) bool { return c < 0x20 || c == 0x7f })
	}
	in.Name, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 64 || !printable(in.Name) {
		groupFieldError(w, r, "name", "group_name_invalid", "give the group a name of 1-64 printable characters")
		return
	}
	if utf8.RuneCountInString(in.Description) > 256 || !printable(in.Description) {
		groupFieldError(w, r, "description", "group_description_invalid", "the description cannot exceed 256 printable characters")
		return
	}
	namespaces, err := s.Local.ValidateGrant(r.Context(), in.Role, in.AllNamespaces, in.AllowNetcheckNamespace, in.Namespaces)
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal", "could not list the users", nil)
		return
	}
	members := []string{}
	for _, m := range in.Members {
		if !slices.ContainsFunc(users, func(u store.User) bool { return u.ID == m }) {
			groupFieldError(w, r, "members", "member_unknown", "one of the members does not exist")
			return
		}
		if !slices.Contains(members, m) {
			members = append(members, m)
		}
	}
	now, actor := time.Now(), identity(r)
	g := store.LocalGroup{ID: id, Name: in.Name, Description: in.Description, Role: in.Role, AllNamespaces: in.AllNamespaces || in.Role == store.RoleAdmin,
		AllowNetcheckNamespace: in.AllowNetcheckNamespace, Namespaces: namespaces, Members: members, CreatedAt: now, UpdatedAt: now, UpdatedBy: actor.Username}
	action, status := "group.update", http.StatusOK
	if id == "" {
		g.ID, action, status = "g"+newID(12), "group.create", http.StatusCreated
	} else {
		prev, err := s.Store.GetGroup(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "not_found", "group not found", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal", "could not read the group", nil)
			return
		}
		g.CreatedAt = prev.CreatedAt
	}
	b, _ := json.Marshal(map[string]any{"groupId": g.ID, "name": g.Name, "role": g.Role, "allNamespaces": g.AllNamespaces,
		"namespaces": g.Namespaces, "members": g.Members})
	ev := store.AuditEvent{ActorID: actor.ID, Action: action, Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(b)}
	if !s.writeGroupError(w, r, s.Store.SaveGroup(r.Context(), g, actor.ID, ev)) {
		return
	}
	s.reloadGroups(r.Context())
	saved, _ := s.Store.GetGroup(r.Context(), g.ID)
	s.Log.Info("group saved", "request_id", RequestID(r.Context()), "actor", actor.Username, "group", g.ID, "name", g.Name)
	writeJSON(w, status, s.groupView(saved))
}

func (s *Server) adminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, actor := r.PathValue("id"), identity(r)
	b, _ := json.Marshal(map[string]any{"groupId": id})
	ev := store.AuditEvent{ActorID: actor.ID, Action: "group.delete", Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(b)}
	if !s.writeGroupError(w, r, s.Store.DeleteGroup(r.Context(), id, actor.ID, ev)) {
		return
	}
	s.reloadGroups(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// writeGroupError answers a failed group change; it reports whether err was nil.
func (s *Server) writeGroupError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "group not found", nil)
	case errors.Is(err, store.ErrGroupExists):
		writeError(w, r, http.StatusConflict, "group_exists", "there is already a group with that name",
			[]probes.FieldError{{Field: "name", Code: "group_exists", Message: "there is already a group with that name"}})
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, r, http.StatusConflict, "last_admin", "the system cannot be left without an active administrator", nil)
	case errors.Is(err, store.ErrSelfAdmin):
		writeError(w, r, http.StatusConflict, "self_admin", "you cannot take away your own administrator role", nil)
	default:
		s.Log.Error("group change failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not change the group", nil)
	}
	return false
}

func (s *Server) reloadGroups(ctx context.Context) {
	if s.Local.Groups == nil {
		return
	}
	if err := s.Local.Groups.Reload(ctx, s.Store); err != nil {
		s.Log.Error("reload groups failed", "error", err)
	}
}

// groupPeers returns the people who share a group with the identity: the
// members of its local groups and the accounts with a single sign-on group in
// common (as of their last sign-in).
func (s *Server) groupPeers(ctx context.Context, id auth.Identity) ([]string, error) {
	peers := s.Local.Groups.Peers(id.ID)
	me, err := s.Store.GetUser(ctx, id.ID)
	if err != nil || len(me.ExternalGroups) == 0 {
		return peers, nil
	}
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID == id.ID || slices.Contains(peers, u.ID) {
			continue
		}
		if slices.ContainsFunc(u.ExternalGroups, func(g string) bool {
			return slices.ContainsFunc(me.ExternalGroups, func(x string) bool { return strings.EqualFold(x, g) })
		}) {
			peers = append(peers, u.ID)
		}
	}
	return peers, nil
}
