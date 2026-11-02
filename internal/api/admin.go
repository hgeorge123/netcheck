package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/store"
)

// setPreferences stores per-user UI preferences (language).
func (s *Server) setPreferences(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Language string `json:"language"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	if err := s.Local.SetLanguage(r.Context(), identity(r), req.Language); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"language": req.Language})
}

// stats aggregates the caller's visible runs for the dashboard.
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 24*90 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "hours must be between 1 and 2160", nil)
			return
		}
		hours = n
	}
	all, allowed := s.Authz.ViewScope(identity(r))
	st, err := s.Store.Stats(r.Context(), store.ListFilter{AllNamespaces: all, AllowedNamespaces: allowed}, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		s.Log.Error("stats failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "total": st.Total, "byStatus": st.ByStatus, "byMethodStatus": st.ByMethodStatus})
}

// SessionView is an active session as shown to administrators.
type SessionView struct {
	ID          string    `json:"id"`
	UserID      string    `json:"userId"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	Role        string    `json:"role"`
	SignedInAt  time.Time `json:"signedInAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	ClientIP    string    `json:"clientIp"`
	UserAgent   string    `json:"userAgent"`
	Current     bool      `json:"current"`
}

func (s *Server) adminSessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.Local.ActiveSessions(r.Context())
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	current, _ := s.Store.GetSession(r.Context(), identity(r).SessionHash)
	items := make([]SessionView, len(list))
	users := map[string]bool{}
	for i, a := range list {
		items[i] = SessionView{ID: a.ID, UserID: a.UserID, Username: a.Username, DisplayName: a.DisplayName, Role: a.Role,
			SignedInAt: a.CreatedAt, LastSeenAt: a.LastSeenAt, ExpiresAt: a.ExpiresAt, ClientIP: a.ClientIP, UserAgent: a.UserAgent,
			Current: a.ID != "" && a.ID == current.ID}
		users[a.UserID] = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "connectedUsers": len(users),
		"idleTimeoutMinutes": int(s.Local.SessionIdle.Minutes())})
}

func (s *Server) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	err := s.Local.RevokeSession(r.Context(), identity(r), r.PathValue("id"), RequestID(r.Context()))
	switch {
	case errors.Is(err, auth.ErrForbiddenSelf):
		writeError(w, r, http.StatusConflict, "self_operation", "use sign out to end your own session", nil)
	case err != nil:
		s.writeUserError(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// VersionView is a NetCheck build as shown in the System page.
type VersionView struct {
	Version       string    `json:"version"`
	Commit        string    `json:"commit"`
	BuildDate     string    `json:"buildDate"`
	Image         string    `json:"image"`
	ProbeImage    string    `json:"probeImage"`
	ChartVersion  string    `json:"chartVersion"`
	FirstSeenAt   time.Time `json:"firstSeenAt"`
	LastStartedAt time.Time `json:"lastStartedAt"`
	Starts        int       `json:"starts"`
}

func versionView(v store.AppVersion) VersionView {
	return VersionView{Version: v.Version, Commit: v.Commit, BuildDate: v.BuildDate, Image: v.Image, ProbeImage: v.ProbeImage,
		ChartVersion: v.ChartVersion, FirstSeenAt: v.FirstSeenAt, LastStartedAt: v.LastStartedAt, Starts: v.Starts}
}

// adminSystem returns the running version, the version history and the
// effective platform settings that affect users.
func (s *Server) adminSystem(w http.ResponseWriter, r *http.Request) {
	history, err := s.Store.ListVersions(r.Context())
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	pv := s.policyView()
	items := make([]VersionView, len(history))
	for i, v := range history {
		items[i] = versionView(v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current":           versionView(s.Version),
		"history":           items,
		"clusterId":         s.ClusterID,
		"namespaceScope":    s.ScopeMode,
		"netcheckNamespace": s.Authz.OwnNamespace,
		"limits": map[string]any{
			"maxChecks":              s.Limits.MaxChecks,
			"maxCheckTimeoutSeconds": int(s.Limits.MaxCheckTimeout.Seconds()),
			"maxJobSeconds":          int(s.Limits.MaxJobDuration.Seconds()),
			"settleSeconds":          int(s.Limits.Settle.Seconds()),
		},
		"destinations":                pv.Policy,
		"protectPlatformDestinations": pv.ProtectPlatformDestinations,
		"destinationsManagedBy":       pv.ManagedBy,
		"retention":                   s.retentionView(),
	})
}
