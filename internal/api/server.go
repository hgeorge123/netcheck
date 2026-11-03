// Package api exposes the versioned REST API (/api/v1), input validation,
// consistent errors and the static Cloudscape frontend.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/diagnostics"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

const maxBodyBytes = 16 << 10

// RunStarter starts the asynchronous execution of a persisted run.
type RunStarter interface {
	Start(run store.Run, spec probes.Spec)
}

// SlotLimiter reserves concurrency slots before a run is accepted.
type SlotLimiter interface {
	TryAcquire(ns string) bool
	Release(ns string)
}

// Server holds API dependencies.
type Server struct {
	Store *store.Store
	Authn auth.Authenticator
	Local *auth.LocalAuth
	// OIDC is single sign-on (nil when disabled); SSOName labels its button.
	OIDC      *auth.OIDC
	SSOName   string
	Authz     *auth.Authorizer
	ScopeMode string
	Starter   RunStarter
	Limiter   SlotLimiter
	// NSAdmin backs Administration > Namespaces (nil disables the page).
	NSAdmin *NamespaceAdmin
	// Policies is the destination policy for new runs (editable by admins).
	Policies *DestinationPolicies
	// TrustedCAs are the certificate authorities HTTPS checks trust on top
	// of the public ones (editable by admins; nil means none).
	TrustedCAs *TrustedCAs
	// Proxies are the HTTP proxies TCP and HTTPS checks may go through
	// (editable by admins; nil means none).
	Proxies *Proxies
	// Retention is how long test data is kept (editable by admins).
	Retention *RetentionSettings
	Limits    probes.Limits
	ClusterID string
	WebDir    string
	Log       *slog.Logger
	// Version describes the running build (shown in the admin System page).
	Version store.AppVersion
}

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.readyz)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/me", s.me)
	api.HandleFunc("GET /api/v1/namespaces", s.namespaces)
	api.HandleFunc("GET /api/v1/probes/catalog", s.catalog)
	api.HandleFunc("POST /api/v1/runs", s.createRun)
	api.HandleFunc("GET /api/v1/runs", s.listRuns)
	api.HandleFunc("GET /api/v1/runs/{id}", s.getRun)
	api.HandleFunc("POST /api/v1/auth/logout", s.logout)
	api.HandleFunc("POST /api/v1/auth/password", s.changePassword)
	api.Handle("GET /api/v1/admin/users", requireAdmin(http.HandlerFunc(s.adminListUsers)))
	api.Handle("POST /api/v1/admin/users", requireAdmin(http.HandlerFunc(s.adminCreateUser)))
	api.Handle("GET /api/v1/admin/users/{id}", requireAdmin(http.HandlerFunc(s.adminGetUser)))
	api.Handle("PUT /api/v1/admin/users/{id}", requireAdmin(http.HandlerFunc(s.adminUpdateUser)))
	api.Handle("DELETE /api/v1/admin/users/{id}", requireAdmin(http.HandlerFunc(s.adminDeleteUser)))
	api.Handle("POST /api/v1/admin/users/{id}/password", requireAdmin(http.HandlerFunc(s.adminResetPassword)))
	api.Handle("POST /api/v1/admin/users/{id}/unlock", requireAdmin(http.HandlerFunc(s.adminUnlock)))
	api.Handle("GET /api/v1/admin/namespaces", requireAdmin(http.HandlerFunc(s.adminNamespaces)))
	api.HandleFunc("PUT /api/v1/me/preferences", s.setPreferences)
	api.HandleFunc("GET /api/v1/me/tokens", s.myTokens)
	api.HandleFunc("POST /api/v1/me/tokens", s.createToken)
	api.HandleFunc("DELETE /api/v1/me/tokens/{id}", s.revokeMyToken)
	api.Handle("GET /api/v1/admin/tokens", requireAdmin(http.HandlerFunc(s.adminTokens)))
	api.Handle("DELETE /api/v1/admin/tokens/{id}", requireAdmin(http.HandlerFunc(s.adminRevokeToken)))
	api.HandleFunc("GET /api/v1/stats", s.stats)
	api.Handle("GET /api/v1/admin/sessions", requireAdmin(http.HandlerFunc(s.adminSessions)))
	api.Handle("DELETE /api/v1/admin/sessions/{id}", requireAdmin(http.HandlerFunc(s.adminRevokeSession)))
	api.Handle("GET /api/v1/admin/system", requireAdmin(http.HandlerFunc(s.adminSystem)))
	api.Handle("GET /api/v1/admin/namespace-exclusions", requireAdmin(http.HandlerFunc(s.adminNamespaceExclusions)))
	api.Handle("POST /api/v1/admin/namespace-exclusions", requireAdmin(http.HandlerFunc(s.adminExcludeNamespace)))
	api.Handle("DELETE /api/v1/admin/namespace-exclusions/{name}", requireAdmin(http.HandlerFunc(s.adminIncludeNamespace)))
	api.Handle("GET /api/v1/admin/policy", requireAdmin(http.HandlerFunc(s.adminPolicy)))
	api.Handle("PUT /api/v1/admin/policy", requireAdmin(http.HandlerFunc(s.adminSetPolicy)))
	api.Handle("POST /api/v1/admin/policy/check", requireAdmin(http.HandlerFunc(s.adminCheckDestination)))
	api.Handle("GET /api/v1/admin/trusted-cas", requireAdmin(http.HandlerFunc(s.adminTrustedCAs)))
	api.Handle("PUT /api/v1/admin/trusted-cas", requireAdmin(http.HandlerFunc(s.adminSetTrustedCAs)))
	api.Handle("GET /api/v1/admin/proxies", requireAdmin(http.HandlerFunc(s.adminProxies)))
	api.Handle("POST /api/v1/admin/proxies", requireAdmin(http.HandlerFunc(s.adminCreateProxy)))
	api.Handle("PUT /api/v1/admin/proxies/{id}", requireAdmin(http.HandlerFunc(s.adminUpdateProxy)))
	api.Handle("DELETE /api/v1/admin/proxies/{id}", requireAdmin(http.HandlerFunc(s.adminDeleteProxy)))
	// Personal proxies: only their owner sees, changes and uses them.
	api.HandleFunc("GET /api/v1/proxies", s.myProxies)
	api.HandleFunc("POST /api/v1/proxies", s.createMyProxy)
	api.HandleFunc("PUT /api/v1/proxies/{id}", s.updateMyProxy)
	api.HandleFunc("DELETE /api/v1/proxies/{id}", s.deleteMyProxy)
	api.Handle("GET /api/v1/admin/retention", requireAdmin(http.HandlerFunc(s.adminRetention)))
	api.Handle("GET /api/v1/admin/access-rules", requireAdmin(http.HandlerFunc(s.adminAccessRules)))
	api.Handle("POST /api/v1/admin/access-rules", requireAdmin(http.HandlerFunc(s.adminSaveAccessRule)))
	api.Handle("PUT /api/v1/admin/access-rules/{id}", requireAdmin(http.HandlerFunc(s.adminSaveAccessRule)))
	api.Handle("DELETE /api/v1/admin/access-rules/{id}", requireAdmin(http.HandlerFunc(s.adminDeleteAccessRule)))
	api.Handle("PUT /api/v1/admin/retention", requireAdmin(http.HandlerFunc(s.adminSetRetention)))
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found", nil)
	})
	// Sign-in endpoints are the only ones reachable without a session. The
	// SSO callback is a cross-site navigation from the provider: it is
	// protected by the state cookie, the PKCE verifier and the nonce.
	mux.Handle("POST /api/v1/auth/login", noStore(withCSRFProtection(http.HandlerFunc(s.login))))
	mux.Handle("GET /api/v1/auth/providers", noStore(http.HandlerFunc(s.providers)))
	mux.Handle("GET /api/v1/auth/oidc/start", noStore(http.HandlerFunc(s.oidcStart)))
	mux.Handle("GET /api/v1/auth/oidc/callback", noStore(http.HandlerFunc(s.oidcCallback)))
	mux.Handle("/api/", noStore(s.authenticated(withCSRFProtection(api))))
	mux.Handle("/", s.static())

	return withRequestContext(s.Log, withSecurityHeaders(mux))
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Authn.Authenticate(r)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "invalid or expired session", nil)
			return
		}
		if id.TokenID != "" && !tokenAllowed(r) {
			writeError(w, r, http.StatusForbidden, "token_scope", auth.ErrTokenScope.Error(), nil)
			return
		}
		// A temporary password only allows reading the profile, choosing the UI
		// language, changing the password and logging out.
		if id.MustChangePassword && !mustChangeAllowed(r) {
			writeError(w, r, http.StatusForbidden, "password_change_required", "you must change your temporary password before continuing", nil)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "not_ready", "database not available", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// static serves the built frontend with SPA fallback to index.html.
func (s *Server) static() http.Handler {
	if s.WebDir == "" {
		return http.NotFoundHandler()
	}
	fs := http.FileServer(http.Dir(s.WebDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		if st, err := os.Stat(filepath.Join(s.WebDir, filepath.FromSlash(clean))); err != nil || st.IsDir() {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fs.ServeHTTP(w, r)
	})
}

func identity(r *http.Request) auth.Identity {
	id, _ := auth.FromContext(r.Context())
	return id
}

func mustChangeAllowed(r *http.Request) bool {
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/me", "PUT /api/v1/me/preferences", "POST /api/v1/auth/password", "POST /api/v1/auth/logout":
		return true
	}
	return false
}

func (s *Server) grants(w http.ResponseWriter, r *http.Request) ([]auth.NamespaceGrant, bool) {
	g, err := s.Authz.Grants(r.Context(), identity(r))
	if err != nil {
		s.Log.Error("namespace listing failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "namespaces_unavailable", "could not list the cluster namespaces", nil)
		return nil, false
	}
	return g, true
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := identity(r)
	body := map[string]any{"id": id.ID, "username": id.Username, "display": id.Display, "role": id.Role,
		"allNamespaces": id.AllNamespaces, "mustChangePassword": id.MustChangePassword, "clusterId": s.ClusterID,
		"namespaceScope": s.ScopeMode, "namespaces": []auth.NamespaceGrant{}, "language": id.Language,
		"allowNetcheckNamespace": id.AllowNetcheckNamespace, "version": s.Version.Version, "source": id.Source}
	if !id.MustChangePassword {
		g, ok := s.grants(w, r)
		if !ok {
			return
		}
		body["namespaces"] = g
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) namespaces(w http.ResponseWriter, r *http.Request) {
	if g, ok := s.grants(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"items": g})
	}
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": probes.Catalog,
		// Proxies the caller may choose for TCP, HTTP and HTTPS checks (optional).
		"proxies": s.catalogProxies(r.Context(), identity(r)),
		"limits": map[string]any{
			"maxChecks":                  s.Limits.MaxChecks,
			"defaultCheckTimeoutSeconds": int(s.Limits.DefaultCheckTimeout.Seconds()),
			"maxCheckTimeoutSeconds":     int(s.Limits.MaxCheckTimeout.Seconds()),
			"maxJobSeconds":              int(s.Limits.MaxJobDuration.Seconds()),
			"settleSeconds":              int(s.Limits.Settle.Seconds()),
		},
	})
}

func (s *Server) audit(r *http.Request, action, ns, runID, outcome string, details map[string]any) {
	b, _ := json.Marshal(details)
	ev := store.AuditEvent{ActorID: identity(r).ID, Action: action, Namespace: ns, RunID: runID, Outcome: outcome,
		RequestID: RequestID(r.Context()), DetailsJSON: string(b)}
	if err := s.Store.InsertAudit(r.Context(), ev); err != nil {
		s.Log.Error("audit write failed", "request_id", ev.RequestID, "action", action, "error", err)
	}
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	id := identity(r)
	var req probes.RunRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	canRun, err := s.Authz.CanRun(r.Context(), id, req.Namespace)
	if err != nil {
		s.Log.Error("namespace listing failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "namespaces_unavailable", "could not list the cluster namespaces", nil)
		return
	}
	if !canRun {
		s.audit(r, "run.create", req.Namespace, "", "forbidden", map[string]any{"reason": "namespace not authorized"})
		writeError(w, r, http.StatusForbidden, "namespace_forbidden", "you are not allowed to run checks in that namespace", nil)
		return
	}
	runID := newID(16)
	proxies, err := s.resolveRunProxies(r.Context(), id, &req)
	var spec probes.Spec
	if err == nil {
		spec, err = probes.BuildSpec(runID, req, s.Policies.Effective(), s.Limits, proxies...)
	}
	if err == nil {
		spec.TrustedCAs = s.TrustedCAs.forSpec(spec)
	}
	var ve probes.ValidationErrors
	var de *probes.DeniedError
	switch {
	case errors.As(err, &ve):
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the request is not valid", ve)
		return
	case errors.As(err, &de):
		s.audit(r, "run.create", req.Namespace, "", "destination_denied", map[string]any{"target": req.Target, "checks": req.Checks, "reason": de.Reason})
		writeError(w, r, http.StatusForbidden, diagnostics.CategoryDestinationDenied, "the destination is not allowed by the NetCheck policy", []probes.FieldError{{Field: "target", Code: "destination_denied", Message: de.Reason}})
		return
	case err != nil:
		s.Log.Error("build spec failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
		return
	}
	if !s.Limiter.TryAcquire(req.Namespace) {
		s.audit(r, "run.create", req.Namespace, "", "rate_limited", map[string]any{"reason": "concurrency limit"})
		w.Header().Set("Retry-After", "10")
		writeError(w, r, http.StatusTooManyRequests, "concurrency_limit", "concurrent checks limit reached; retry in a few seconds", nil)
		return
	}
	reqJSON, _ := json.Marshal(req)
	specJSON, _ := json.Marshal(spec)
	run := store.Run{ID: runID, CreatedAt: time.Now(), ActorID: id.ID, ActorDisplay: id.Display, Namespace: req.Namespace,
		ClusterID: s.ClusterID, Target: spec.Target.Raw, Status: store.RunQueued, RequestJSON: string(reqJSON), SpecJSON: string(specJSON)}
	execs := make([]store.Execution, len(spec.Checks))
	for i, c := range spec.Checks {
		execs[i] = store.Execution{ID: runID + "-" + strconv.Itoa(i+1), Seq: i + 1, CheckID: c.ID, Method: string(c.Method), Status: store.RunQueued}
	}
	ev := store.AuditEvent{ActorID: id.ID, Action: "run.create", Namespace: req.Namespace, RunID: runID, Outcome: "accepted",
		RequestID: RequestID(r.Context()), DetailsJSON: string(reqJSON)}
	if err := s.Store.CreateRun(r.Context(), run, execs, ev); err != nil {
		s.Limiter.Release(req.Namespace)
		s.Log.Error("create run failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not record the run", nil)
		return
	}
	s.Starter.Start(run, spec)
	w.Header().Set("Location", "/api/v1/runs/"+runID)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": runID, "status": store.RunQueued})
}

// runFilter restricts history and statistics to what the identity may read:
// every test for administrators, otherwise only the tests it started.
func runFilter(id auth.Identity) store.ListFilter {
	all, own := auth.RunScope(id)
	if all {
		return store.ListFilter{AllNamespaces: true}
	}
	return store.ListFilter{AllNamespaces: true, ActorID: own}
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	id := identity(r)
	q := r.URL.Query()
	f := runFilter(id)
	f.Namespace, f.Status, f.Cursor = q.Get("namespace"), q.Get("status"), q.Get("cursor")
	if v := q.Get("pageSize"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "pageSize must be between 1 and 100", nil)
			return
		}
		f.PageSize = n
	}
	if f.Status != "" && !validRunStatus(f.Status) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "invalid status", nil)
		return
	}
	for _, p := range []struct {
		key string
		dst **time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if v := q.Get(p.key); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "validation_failed", p.key+" must be RFC3339", nil)
				return
			}
			*p.dst = &t
		}
	}
	runs, next, err := s.Store.ListRuns(r.Context(), f)
	if errors.Is(err, store.ErrInvalidCursor) {
		writeError(w, r, http.StatusBadRequest, "invalid_cursor", "invalid cursor", nil)
		return
	}
	if err != nil {
		s.Log.Error("list runs failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
		return
	}
	items := make([]RunSummary, len(runs))
	for i, run := range runs {
		items[i] = summary(run)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

func validRunStatus(s string) bool {
	switch s {
	case store.RunQueued, store.RunRunning, store.RunSucceeded, store.RunFailed, store.RunCancelled, store.RunInfraError:
		return true
	}
	return false
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if !probes.ValidRunID(runID) {
		writeError(w, r, http.StatusNotFound, "not_found", "run not found", nil)
		return
	}
	run, execs, err := s.Store.GetRun(r.Context(), runID)
	// Unauthorized and missing runs are indistinguishable to the caller.
	if errors.Is(err, store.ErrNotFound) || (err == nil && !auth.CanViewRun(identity(r), run.ActorID)) {
		writeError(w, r, http.StatusNotFound, "not_found", "run not found", nil)
		return
	}
	if err != nil {
		s.Log.Error("get run failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
		return
	}
	d := detail(run, execs)
	if identity(r).ID != run.ActorID {
		// Only the author sees the details of personal proxies.
		hidePersonalProxies(&d)
	}
	writeJSON(w, http.StatusOK, d)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errors.New("request body too large")
		}
		return errors.New("invalid JSON or unknown fields")
	}
	if dec.More() {
		return errors.New("a single JSON object was expected")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, `{"error":{"code":"internal","message":"encoding error"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// ErrorBody is the consistent error envelope.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"requestId"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string, details any) {
	writeJSON(w, status, map[string]ErrorBody{"error": {Code: code, Message: msg, Details: details, RequestID: RequestID(r.Context())}})
}
