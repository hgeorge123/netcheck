package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// SharedProxy is an administrators' proxy of the configuration (Helm values).
type SharedProxy struct {
	probes.Proxy
	// Shared lets every user choose it; otherwise only administrators.
	Shared bool
}

// Proxies manages the HTTP proxies checks may go through: administrators'
// proxies, shared with every user or kept for administrators, which only
// administrators change; and personal proxies, which only their owner sees,
// changes and uses. Administrators' proxies live in the database (seeded once
// from the Helm values) or, when managed in Helm, come from the values only.
type Proxies struct {
	st   *store.Store
	helm []store.ProxyRecord // administrators' proxies managed in Helm; nil otherwise
}

// LoadProxies returns the proxies of a server. With editable=true the
// administrators' proxies of the configuration seed the database once;
// otherwise they are authoritative and read-only.
func LoadProxies(ctx context.Context, st *store.Store, seed []SharedProxy, editable bool, now time.Time) (*Proxies, error) {
	recs := make([]store.ProxyRecord, 0, len(seed))
	names := make([]probes.Proxy, len(seed))
	for i, s := range seed {
		names[i] = s.Proxy
	}
	norm, err := probes.NormalizeProxies(names)
	if err != nil {
		return nil, fmt.Errorf("proxies in the configuration: %w", err)
	}
	for i, p := range norm {
		id := "helm-" + p.Name
		if editable {
			id = store.NewProxyID()
		}
		recs = append(recs, store.ProxyRecord{ID: id, Name: p.Name, Host: p.Host, Port: p.Port, Shared: seed[i].Shared,
			CAsJSON: casJSON(p.TrustedCAs), CreatedAt: now, UpdatedAt: now, UpdatedBy: SeedPolicyActor})
	}
	h := &Proxies{st: st}
	if !editable {
		h.helm = recs
		return h, nil
	}
	b, _ := json.Marshal(proxyAudit(recs))
	if _, err := st.SeedProxies(ctx, recs, now, store.AuditEvent{ActorID: "system:helm", Action: "proxies.seed", Outcome: "success",
		DetailsJSON: string(b)}); err != nil {
		return nil, fmt.Errorf("seed proxies: %w", err)
	}
	return h, nil
}

func casJSON(cas []string) string {
	if len(cas) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(cas)
	return string(b)
}

func recordCAs(r store.ProxyRecord) []string {
	var cas []string
	_ = json.Unmarshal([]byte(r.CAsJSON), &cas)
	if len(cas) == 0 {
		return nil
	}
	return cas
}

// all returns the administrators' proxies and every personal proxy.
func (h *Proxies) all(ctx context.Context) ([]store.ProxyRecord, error) {
	rows, err := h.st.ListProxies(ctx)
	if err != nil || h.helm == nil {
		return rows, err
	}
	out := append([]store.ProxyRecord{}, h.helm...)
	for _, r := range rows {
		if r.OwnerID != "" {
			out = append(out, r)
		}
	}
	return out, nil
}

// visible returns the proxies the identity may see and use: shared ones,
// administrators-only ones for administrators, and its own personal ones.
func (h *Proxies) visible(ctx context.Context, id auth.Identity) ([]store.ProxyRecord, error) {
	if h == nil {
		return nil, nil
	}
	rows, err := h.all(ctx)
	if err != nil {
		return nil, err
	}
	out := []store.ProxyRecord{}
	for _, r := range rows {
		if (r.OwnerID == "" && (r.Shared || id.IsAdmin())) || (r.OwnerID != "" && r.OwnerID == id.ID) {
			out = append(out, r)
		}
	}
	return out, nil
}

func toProbeProxy(r store.ProxyRecord) probes.Proxy {
	return probes.Proxy{ID: r.ID, Name: r.Name, Host: r.Host, Port: r.Port, Personal: r.OwnerID != "", TrustedCAs: recordCAs(r)}
}

// errProxyAmbiguous: a name matches both a personal and a shared proxy.
var errProxyAmbiguous = errors.New("ambiguous proxy name")

// resolve finds the proxy a check names, among those the identity may use:
// by ID, otherwise by name (personal first). A name of both a personal and a
// shared proxy is ambiguous. ok=false means no such proxy.
func (h *Proxies) resolve(ctx context.Context, id auth.Identity, ref string) (probes.Proxy, bool, error) {
	rows, err := h.visible(ctx, id)
	if err != nil {
		return probes.Proxy{}, false, err
	}
	var personal, shared *store.ProxyRecord
	for i, r := range rows {
		if r.ID == ref {
			return toProbeProxy(r), true, nil
		}
		if r.Name == ref {
			if r.OwnerID != "" {
				personal = &rows[i]
			} else {
				shared = &rows[i]
			}
		}
	}
	switch {
	case personal != nil && shared != nil:
		return probes.Proxy{}, false, errProxyAmbiguous
	case personal != nil:
		return toProbeProxy(*personal), true, nil
	case shared != nil:
		return toProbeProxy(*shared), true, nil
	}
	return probes.Proxy{}, false, nil
}

// resolveRunProxies replaces the proxy named by each check with its ID and
// returns the proxies for BuildSpec. Unknown names are left for BuildSpec to
// report.
func (s *Server) resolveRunProxies(ctx context.Context, id auth.Identity, req *probes.RunRequest) ([]probes.Proxy, error) {
	var out []probes.Proxy
	var errs probes.ValidationErrors
	for i := range req.Checks {
		ref := req.Checks[i].Proxy
		if ref == "" || s.Proxies == nil {
			continue
		}
		p, ok, err := s.Proxies.resolve(ctx, id, ref)
		switch {
		case errors.Is(err, errProxyAmbiguous):
			errs = append(errs, probes.FieldError{Field: fmt.Sprintf("checks[%d].proxy", i), Code: "proxy_ambiguous",
				Message: fmt.Sprintf("%q names both one of your proxies and a shared proxy: choose it by ID", ref)})
		case err != nil:
			return nil, err
		case ok:
			req.Checks[i].Proxy = p.ID
			out = append(out, p)
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return out, nil
}

// ProxyView describes a proxy. Certificates are listed only to whoever may
// manage the proxy; users choosing a proxy see how many it has.
type ProxyView struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	Personal         bool              `json:"personal"`
	Shared           bool              `json:"shared"`
	CertificateCount int               `json:"certificateCount"`
	Certificates     []CertificateView `json:"certificates,omitempty"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	UpdatedBy        string            `json:"updatedBy"`
}

func proxyView(r store.ProxyRecord, withCerts bool, now time.Time) ProxyView {
	cas := recordCAs(r)
	v := ProxyView{ID: r.ID, Name: r.Name, Host: r.Host, Port: r.Port, Personal: r.OwnerID != "", Shared: r.OwnerID == "" && r.Shared,
		CertificateCount: len(cas), UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
	if withCerts {
		certs, _ := probes.ParseTrustedCAs(cas)
		v.Certificates = []CertificateView{}
		for i, c := range certs {
			v.Certificates = append(v.Certificates, certificateView(cas[i], c, now))
		}
	}
	return v
}

// catalogProxies lists the proxies the identity may choose for its checks.
func (s *Server) catalogProxies(ctx context.Context, id auth.Identity) []ProxyView {
	rows, err := s.Proxies.visible(ctx, id)
	if err != nil {
		s.Log.Error("list proxies failed", "error", err)
	}
	out := []ProxyView{}
	for _, r := range rows {
		out = append(out, proxyView(r, false, time.Now()))
	}
	return out
}

// proxyAudit describes proxies for the audit log: name, address, sharing and
// the subject and fingerprint of their authorities, never the PEM.
func proxyAudit(rows []store.ProxyRecord) []map[string]any {
	out := []map[string]any{}
	for _, r := range rows {
		certs, _ := probes.ParseTrustedCAs(recordCAs(r))
		cas := []map[string]string{}
		for _, c := range certs {
			cas = append(cas, map[string]string{"subject": c.Subject.String(), "fingerprintSha256": probes.Fingerprint(c)})
		}
		out = append(out, map[string]any{"id": r.ID, "name": r.Name, "address": fmt.Sprintf("%s:%d", r.Host, r.Port),
			"personal": r.OwnerID != "", "owner": r.OwnerID, "shared": r.Shared, "certificates": cas})
	}
	return out
}

// ProxyInput is the body to create or change a proxy.
type ProxyInput struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Shared       bool     `json:"shared"`
	Certificates []string `json:"certificates"`
}

func (s *Server) adminProxies(w http.ResponseWriter, r *http.Request) {
	s.listProxies(w, r, "")
}

func (s *Server) myProxies(w http.ResponseWriter, r *http.Request) {
	s.listProxies(w, r, identity(r).ID)
}

// listProxies lists the administrators' proxies (ownerID "") or the
// caller's personal ones, with their certificates.
func (s *Server) listProxies(w http.ResponseWriter, r *http.Request, ownerID string) {
	rows, err := s.Proxies.all(r.Context())
	if err != nil {
		s.Log.Error("list proxies failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not list the proxies", nil)
		return
	}
	now := time.Now()
	items := []ProxyView{}
	for _, p := range rows {
		if p.OwnerID == ownerID {
			items = append(items, proxyView(p, true, now))
		}
	}
	limit, editable, managed := probes.MaxPersonalProxies, true, "ui"
	if ownerID == "" {
		limit = probes.MaxProxies
		if s.Proxies.helm != nil {
			editable, managed = false, "helm"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": items, "max": limit, "editable": editable, "managedBy": managed})
}

func (s *Server) adminCreateProxy(w http.ResponseWriter, r *http.Request) { s.saveProxy(w, r, "", "") }
func (s *Server) adminUpdateProxy(w http.ResponseWriter, r *http.Request) {
	s.saveProxy(w, r, "", r.PathValue("id"))
}
func (s *Server) adminDeleteProxy(w http.ResponseWriter, r *http.Request) {
	s.deleteProxy(w, r, "", r.PathValue("id"))
}
func (s *Server) createMyProxy(w http.ResponseWriter, r *http.Request) {
	s.saveProxy(w, r, identity(r).ID, "")
}
func (s *Server) updateMyProxy(w http.ResponseWriter, r *http.Request) {
	s.saveProxy(w, r, identity(r).ID, r.PathValue("id"))
}
func (s *Server) deleteMyProxy(w http.ResponseWriter, r *http.Request) {
	s.deleteProxy(w, r, identity(r).ID, r.PathValue("id"))
}

func (s *Server) proxiesReadOnly(w http.ResponseWriter, r *http.Request, ownerID string) bool {
	if ownerID == "" && s.Proxies.helm != nil {
		writeError(w, r, http.StatusConflict, "proxies_managed_by_helm", "the shared proxies are managed in the Helm values (proxiesManagedBy: helm)", nil)
		return true
	}
	return false
}

// saveProxy creates (id "") or changes a proxy of ownerID ("" for the
// administrators' proxies). A personal proxy is never shared.
func (s *Server) saveProxy(w http.ResponseWriter, r *http.Request, ownerID, id string) {
	if s.proxiesReadOnly(w, r, ownerID) {
		return
	}
	var in ProxyInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	p, err := probes.NormalizeProxy(probes.Proxy{Name: strings.TrimSpace(in.Name), Host: in.Host, Port: in.Port, TrustedCAs: in.Certificates})
	var fe probes.FieldError
	if errors.As(err, &fe) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the proxy is not valid", []probes.FieldError{fe})
		return
	}
	// The Pod connects to the proxy: it must be a destination the policy allows.
	compiled, err := s.Policies.Effective().Compile()
	if err == nil {
		err = compiled.CheckProxy(p)
	}
	var de *probes.DeniedError
	if errors.As(err, &de) {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the proxy is not allowed by the destination policy",
			[]probes.FieldError{{Field: "host", Code: "proxy_denied", Message: de.Reason}})
		return
	} else if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal", "invalid policy", nil)
		return
	}
	who := identity(r)
	now := time.Now()
	rec := store.ProxyRecord{ID: id, OwnerID: ownerID, Name: p.Name, Host: p.Host, Port: p.Port, Shared: ownerID == "" && in.Shared,
		CAsJSON: casJSON(p.TrustedCAs), CreatedAt: now, UpdatedAt: now, UpdatedBy: who.Username}
	action := "proxies.update"
	if id == "" {
		action, rec.ID = "proxies.create", store.NewProxyID()
		limit := probes.MaxPersonalProxies
		if ownerID == "" {
			limit = probes.MaxProxies
		}
		if n, err := s.Store.CountProxies(r.Context(), ownerID); err != nil || n >= limit {
			if err == nil {
				writeError(w, r, http.StatusBadRequest, "validation_failed", "too many proxies",
					[]probes.FieldError{{Field: "proxies", Code: "too_many_proxies", Message: fmt.Sprintf("at most %d proxies", limit)}})
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal", "could not count the proxies", nil)
			return
		}
	}
	details, _ := json.Marshal(proxyAudit([]store.ProxyRecord{rec}))
	ev := store.AuditEvent{ActorID: who.ID, Action: action, Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(details)}
	if id == "" {
		err = s.Store.CreateProxy(r.Context(), rec, ev)
	} else {
		err = s.Store.UpdateProxy(r.Context(), rec, ev)
	}
	switch {
	case errors.Is(err, store.ErrProxyExists):
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the proxy is not valid",
			[]probes.FieldError{{Field: "name", Code: "duplicate_proxy_name", Message: "there is already a proxy with that name"}})
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "proxy not found", nil)
		return
	case err != nil:
		s.Log.Error("save proxy failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the proxy", nil)
		return
	}
	s.Log.Info("proxy saved", "request_id", RequestID(r.Context()), "actor", who.Username, "proxy", rec.ID, "personal", ownerID != "")
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, proxyView(rec, true, now))
}

func (s *Server) deleteProxy(w http.ResponseWriter, r *http.Request, ownerID, id string) {
	if s.proxiesReadOnly(w, r, ownerID) {
		return
	}
	who := identity(r)
	var target []store.ProxyRecord
	if rows, err := s.Proxies.all(r.Context()); err == nil {
		for _, p := range rows {
			if p.ID == id && p.OwnerID == ownerID {
				target = append(target, p)
			}
		}
	}
	details, _ := json.Marshal(proxyAudit(target))
	err := s.Store.DeleteProxy(r.Context(), id, ownerID, store.AuditEvent{ActorID: who.ID, Action: "proxies.delete", Outcome: "success",
		RequestID: RequestID(r.Context()), DetailsJSON: string(details)})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "proxy not found", nil)
	case err != nil:
		s.Log.Error("delete proxy failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not delete the proxy", nil)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// personalProxyLabel replaces a personal proxy's details for anyone but the
// user who ran the test.
const personalProxyLabel = "[personal proxy]"

// hidePersonalProxies removes the name, address and IPs of personal proxies
// from a test shown to someone other than its author (administrators).
func hidePersonalProxies(d *RunDetail) {
	var req probes.RunRequest
	reqChanged := json.Unmarshal(d.Request, &req) == nil
	changed := false
	for i := range d.Checks {
		c := &d.Checks[i]
		var cr probes.CheckResult
		if len(c.Result) == 0 || json.Unmarshal(c.Result, &cr) != nil || cr.Proxy == nil || !cr.Proxy.Personal {
			continue
		}
		p := cr.Proxy
		// Longest first: the address before its host name.
		secrets := []string{"http://" + p.Address, p.Address}
		if host, _, err := net.SplitHostPort(p.Address); err == nil && host != "" {
			secrets = append(secrets, host) // e.g. "resolved <host> (ip)" in the output
		}
		if p.UsedIP != "" {
			secrets = append(secrets, p.UsedIP)
		}
		secrets = append(secrets, p.ResolvedIPs...)
		// The probe writes the name as "proxy <name>" (output, errors, diagnosis).
		named := regexp.MustCompile(`\bproxy ` + regexp.QuoteMeta(p.Name) + `\b`)
		replacer := func(s string) string {
			s = named.ReplaceAllLiteralString(s, "proxy "+personalProxyLabel)
			for _, x := range secrets {
				if x != "" {
					s = strings.ReplaceAll(s, x, personalProxyLabel)
				}
			}
			return s
		}
		c.Output, c.Error = replacer(c.Output), replacer(c.Error)
		var argv []string
		if json.Unmarshal(c.Equivalent, &argv) == nil {
			for j := range argv {
				argv[j] = replacer(argv[j])
			}
			c.Equivalent, _ = json.Marshal(argv)
		}
		var diag map[string]any
		if json.Unmarshal(c.Diagnosis, &diag) == nil {
			delete(diag, "proxy")
			if s, ok := diag["detail"].(string); ok {
				diag["detail"] = replacer(s)
			}
			c.Diagnosis, _ = json.Marshal(diag)
		}
		// The result keeps its own copy of the output, error and command.
		cr.Error, cr.Output = replacer(cr.Error), replacer(cr.Output)
		for j := range cr.Equivalent {
			cr.Equivalent[j] = replacer(cr.Equivalent[j])
		}
		cr.Proxy = &probes.ProxyResult{Personal: true, Mode: p.Mode, Reached: p.Reached, Status: p.Status, StatusText: p.StatusText}
		c.Result, _ = json.Marshal(cr)
		// The request named the proxy too.
		var n int
		if _, err := fmt.Sscanf(c.CheckID, "%d-", &n); err == nil && reqChanged && n >= 1 && n <= len(req.Checks) && req.Checks[n-1].Proxy != "" {
			req.Checks[n-1].Proxy = personalProxyLabel
			changed = true
		}
	}
	if changed {
		d.Request, _ = json.Marshal(req)
	}
}

func certificateView(pem string, c *x509.Certificate, now time.Time) CertificateView {
	return CertificateView{PEM: pem, Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Fingerprint: probes.Fingerprint(c), Expired: now.After(c.NotAfter)}
}
