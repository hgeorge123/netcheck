package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"time"
)

type ctxKey int

const requestIDKey ctxKey = iota

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// RequestID returns the request id stored in ctx.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withRequestContext assigns a request id, recovers panics and logs requests
// as JSON without query strings (they may carry filters with identifiers).
func withRequestContext(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !requestIDPattern.MatchString(id) {
			id = newID(12)
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if p := recover(); p != nil {
				log.Error("panic", "request_id", id, "panic", p, "stack", string(debug.Stack()))
				writeError(rec, r.WithContext(ctx), http.StatusInternalServerError, "internal", "internal error", nil)
			}
			log.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}

// withSecurityHeaders applies a restrictive CSP and standard hardening headers.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// withCSRFProtection rejects cross-site state-changing requests. Mutating
// requests must be JSON (not sendable by plain HTML forms), must not be
// cross-site per Fetch Metadata, and any Origin must match the Host.
func withCSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// DELETE carries no body and cannot be sent by HTML forms; cross-site
		// fetch would need a CORS preflight, which is never granted.
		if r.Method != http.MethodDelete {
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/json" {
				writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type: application/json is required", nil)
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, r, http.StatusForbidden, "csrf_rejected", "cross-site request rejected", nil)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				writeError(w, r, http.StatusForbidden, "csrf_rejected", "origin not allowed", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
