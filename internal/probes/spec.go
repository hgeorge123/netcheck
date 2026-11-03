package probes

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// CatalogEntry describes a supported method for the UI and API clients.
type CatalogEntry struct {
	Method       Method `json:"method"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	RequiresPort bool   `json:"requiresPort"`
	DefaultPort  int    `json:"defaultPort,omitempty"`
	HostnameOnly bool   `json:"hostnameOnly"`
}

// ICMP timing: one probe per second, each waiting up to perProbeWait.
const (
	perProbeWait      = time.Second
	DefaultPingCount  = 4
	MaxPingCount      = 10
	DefaultMaxHops    = 20
	MaxTracerouteHops = 30
)

// Catalog is the fixed allowlist of methods. Labels and descriptions are
// English fallbacks; the UI translates by method.
var Catalog = []CatalogEntry{
	{Method: MethodDNS, Label: "DNS resolution", Description: "Resolves A/AAAA and CNAME with the source Pod resolver.", HostnameOnly: true},
	{Method: MethodTCP, Label: "TCP connection", Description: "Opens a TCP connection (like nc -z or telnet) without speaking any protocol.", RequiresPort: true},
	{Method: MethodUDP, Label: "UDP", Description: "Sends a fixed datagram: generic (inconclusive without a reply), a DNS query or an NTP request.", RequiresPort: true},
	{Method: MethodHTTP, Label: "HTTP", Description: "GET or HEAD request over plain HTTP; redirects are not followed.", RequiresPort: true, DefaultPort: 80},
	{Method: MethodHTTPS, Label: "HTTPS", Description: "GET or HEAD request over TLS with certificate verification; redirects are not followed.", RequiresPort: true, DefaultPort: 443},
	{Method: MethodPing, Label: "Ping (ICMP)", Description: "ICMP echo requests. ICMP may be filtered even when TCP works."},
	{Method: MethodTraceroute, Label: "Traceroute (ICMP)", Description: "Path discovery with increasing TTL. Silent hops do not prove packet loss."},
}

// UDPDefaultPort is the default port of a UDP protocol; generic needs one.
func UDPDefaultPort(protocol string) int {
	switch protocol {
	case UDPDNS:
		return 53
	case UDPNTP:
		return 123
	}
	return 0
}

func validUDPProtocol(p string) bool { return p == UDPGeneric || p == UDPDNS || p == UDPNTP }

func catalogEntry(m Method) (CatalogEntry, bool) {
	for _, e := range Catalog {
		if e.Method == m {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// CheckRequest is one requested check in the API payload.
type CheckRequest struct {
	Method     Method             `json:"method"`
	Port       int                `json:"port,omitempty"`
	DNS        *DNSOptions        `json:"dns,omitempty"`
	HTTP       *HTTPOptions       `json:"http,omitempty"`
	UDP        *UDPOptions        `json:"udp,omitempty"`
	Ping       *PingOptions       `json:"ping,omitempty"`
	Traceroute *TracerouteOptions `json:"traceroute,omitempty"`
}

// Run modes. ModeFirewall marks a run created by the "firewall ticket"
// form; the checks are ordinary ones, the UI renders a single report.
const ModeFirewall = "firewall"

// RunRequest is the API payload for POST /api/v1/runs.
type RunRequest struct {
	Mode           string         `json:"mode,omitempty"`
	Namespace      string         `json:"namespace"`
	Target         string         `json:"target"`
	TimeoutSeconds int            `json:"timeoutSeconds,omitempty"`
	Checks         []CheckRequest `json:"checks"`
}

// Limits bounds what a single run may request.
type Limits struct {
	MaxChecks           int
	DefaultCheckTimeout time.Duration
	MaxCheckTimeout     time.Duration
	MaxJobDuration      time.Duration
	MaxOutputBytes      int
	Settle              time.Duration
}

// jobOverhead is reserved inside the Job deadline for process start-up and
// result printing.
const jobOverhead = 5 * time.Second

var runIDPattern = regexp.MustCompile(`^[a-z0-9]{8,40}$`)

// ValidRunID reports whether id is safe to use in Job names and labels.
func ValidRunID(id string) bool { return runIDPattern.MatchString(id) }

// PingTimeout is the time budget of a ping check with count probes.
func PingTimeout(count int) time.Duration { return time.Duration(count)*perProbeWait + time.Second }

// TracerouteTimeout is the time budget of a traceroute with maxHops.
func TracerouteTimeout(maxHops int) time.Duration {
	return time.Duration(maxHops)*perProbeWait + time.Second
}

// BuildSpec validates a request and builds the immutable probe spec. It
// returns ValidationErrors for malformed input and *DeniedError when the
// destination or a port is rejected by policy.
func BuildSpec(runID string, req RunRequest, policy DestinationPolicy, lim Limits) (Spec, error) {
	compiled, err := policy.Compile()
	if err != nil {
		return Spec{}, fmt.Errorf("invalid destination policy: %w", err)
	}
	var errs ValidationErrors
	target, terr := ParseTarget(req.Target)
	if terr != nil {
		var fe FieldError
		if errors.As(terr, &fe) {
			errs = append(errs, fe)
		}
	}

	timeout := lim.DefaultCheckTimeout
	if req.TimeoutSeconds != 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
		if req.TimeoutSeconds < 1 || timeout > lim.MaxCheckTimeout {
			errs = append(errs, fieldErr("timeoutSeconds", "out_of_range", "the timeout must be between 1 and %d seconds", int(lim.MaxCheckTimeout.Seconds())))
		}
	}
	errs = append(errs, validateChecksShape(req.Checks, lim)...)
	if req.Mode != "" && req.Mode != ModeFirewall {
		errs = append(errs, fieldErr("mode", "invalid_mode", "unknown run mode"))
	}

	checks := make([]Check, 0, len(req.Checks))
	var total time.Duration
	for i, cr := range req.Checks {
		entry, ok := catalogEntry(cr.Method)
		if !ok {
			continue // reported by validateChecksShape
		}
		field := fmt.Sprintf("checks[%d]", i)
		c := Check{ID: fmt.Sprintf("%d-%s", i+1, cr.Method), Method: cr.Method, TimeoutMS: int(timeout.Milliseconds())}
		if entry.HostnameOnly && terr == nil && target.IsIP {
			errs = append(errs, fieldErr(field, "hostname_required", "the %s check needs a hostname, not an IP address", cr.Method))
		}
		// Ports: required for TCP and generic UDP, defaulted for HTTP/HTTPS and
		// UDP DNS/NTP, forbidden otherwise.
		defaultPort := entry.DefaultPort
		if cr.Method == MethodUDP && cr.UDP != nil {
			defaultPort = UDPDefaultPort(cr.UDP.Protocol)
		}
		switch {
		case entry.RequiresPort && cr.Port == 0 && defaultPort != 0:
			c.Port = defaultPort
		case entry.RequiresPort && cr.Port == 0:
			errs = append(errs, fieldErr(field+".port", "port_required", "the %s check needs a port", cr.Method))
		case entry.RequiresPort:
			if err := ValidatePort(cr.Port); err != nil {
				fe := err.(FieldError)
				fe.Field = field + ".port"
				errs = append(errs, fe)
			}
			c.Port = cr.Port
		case cr.Port != 0:
			errs = append(errs, fieldErr(field+".port", "port_not_applicable", "the %s check does not use a port", cr.Method))
		}
		if (cr.HTTP != nil && cr.Method != MethodHTTP && cr.Method != MethodHTTPS) || (cr.DNS != nil && cr.Method != MethodDNS) ||
			(cr.Ping != nil && cr.Method != MethodPing) || (cr.Traceroute != nil && cr.Method != MethodTraceroute) ||
			(cr.UDP != nil && cr.Method != MethodUDP) {
			errs = append(errs, fieldErr(field, "unexpected_options", "options not applicable to the %s check", cr.Method))
		}
		switch cr.Method {
		case MethodDNS:
			opts := DNSOptions{Family: "ip"}
			if cr.DNS != nil && cr.DNS.Family != "" {
				opts.Family = cr.DNS.Family
			}
			if opts.Family != "ip" && opts.Family != "ip4" && opts.Family != "ip6" {
				errs = append(errs, fieldErr(field+".dns.family", "invalid_family", "invalid DNS family"))
			}
			c.DNS = &opts
		case MethodHTTP, MethodHTTPS:
			opts := HTTPOptions{Method: "GET", Path: "/"}
			if cr.HTTP != nil {
				if cr.HTTP.Method != "" {
					opts.Method = cr.HTTP.Method
				}
				if cr.HTTP.Path != "" {
					opts.Path = cr.HTTP.Path
				}
				opts.IgnoreTLSErrors = cr.HTTP.IgnoreTLSErrors
			}
			if opts.IgnoreTLSErrors && cr.Method != MethodHTTPS {
				errs = append(errs, fieldErr(field+".http.ignoreTlsErrors", "ignore_tls_https_only", "certificate errors can only be ignored for HTTPS"))
			}
			if opts.Method != "GET" && opts.Method != "HEAD" {
				errs = append(errs, fieldErr(field+".http.method", "invalid_http_method", "only GET or HEAD are allowed"))
			}
			if err := ValidatePath(opts.Path); err != nil {
				fe := err.(FieldError)
				fe.Field = field + ".http.path"
				errs = append(errs, fe)
			}
			c.HTTP = &opts
		case MethodUDP:
			opts := UDPOptions{Protocol: UDPGeneric}
			if cr.UDP != nil && cr.UDP.Protocol != "" {
				opts.Protocol = cr.UDP.Protocol
			}
			if !validUDPProtocol(opts.Protocol) {
				errs = append(errs, fieldErr(field+".udp.protocol", "invalid_udp_protocol", "the UDP protocol must be generic, dns or ntp"))
			}
			c.UDP = &opts
		case MethodPing:
			opts := PingOptions{Count: DefaultPingCount}
			if cr.Ping != nil && cr.Ping.Count != 0 {
				opts.Count = cr.Ping.Count
			}
			if opts.Count < 1 || opts.Count > MaxPingCount {
				errs = append(errs, fieldErr(field+".ping.count", "out_of_range", "the ping count must be between 1 and %d", MaxPingCount))
			}
			c.Ping = &opts
			c.TimeoutMS = int(PingTimeout(opts.Count).Milliseconds())
		case MethodTraceroute:
			opts := TracerouteOptions{MaxHops: DefaultMaxHops}
			if cr.Traceroute != nil && cr.Traceroute.MaxHops != 0 {
				opts.MaxHops = cr.Traceroute.MaxHops
			}
			if opts.MaxHops < 1 || opts.MaxHops > MaxTracerouteHops {
				errs = append(errs, fieldErr(field+".traceroute.maxHops", "out_of_range", "max hops must be between 1 and %d", MaxTracerouteHops))
			}
			c.Traceroute = &opts
			c.TimeoutMS = int(TracerouteTimeout(opts.MaxHops).Milliseconds())
		}
		total += time.Duration(c.TimeoutMS) * time.Millisecond
		checks = append(checks, c)
	}

	if budget := lim.Settle + jobOverhead + total; budget > lim.MaxJobDuration {
		errs = append(errs, fieldErr("checks", "budget_exceeded", "the checks need up to %s, more than the maximum Job duration (%s); lower timeouts, ping count or max hops",
			budget.Round(time.Second), lim.MaxJobDuration))
	}
	if len(errs) > 0 {
		return Spec{}, errs
	}

	if err := compiled.CheckHost(target); err != nil {
		return Spec{}, err
	}
	for _, c := range checks {
		if c.Port != 0 {
			if err := compiled.CheckPort(c.Port); err != nil {
				return Spec{}, err
			}
		}
	}

	spec := Spec{
		SchemaVersion:  SchemaVersion,
		RunID:          runID,
		Target:         target,
		Checks:         checks,
		Policy:         policy,
		MaxOutputBytes: lim.MaxOutputBytes,
		SettleMS:       int(lim.Settle.Milliseconds()),
	}
	if err := spec.Validate(); err != nil {
		return Spec{}, fmt.Errorf("internal spec validation failed: %w", err)
	}
	return spec, nil
}

func validateChecksShape(checks []CheckRequest, lim Limits) ValidationErrors {
	var errs ValidationErrors
	if len(checks) == 0 {
		errs = append(errs, fieldErr("checks", "required", "select at least one check"))
	}
	if len(checks) > lim.MaxChecks {
		errs = append(errs, fieldErr("checks", "too_many", "at most %d checks per run", lim.MaxChecks))
	}
	seen := map[Method]bool{}
	for i, c := range checks {
		if _, ok := catalogEntry(c.Method); !ok {
			errs = append(errs, fieldErr(fmt.Sprintf("checks[%d].method", i), "unknown_method", "method not allowed"))
			continue
		}
		if seen[c.Method] {
			errs = append(errs, fieldErr(fmt.Sprintf("checks[%d].method", i), "duplicate_method", "method repeated in the run"))
		}
		seen[c.Method] = true
	}
	return errs
}

// Validate re-checks a spec. The probe calls it before executing anything so
// a tampered or malformed spec never reaches the network.
func (s Spec) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %q", s.SchemaVersion)
	}
	if !ValidRunID(s.RunID) {
		return errors.New("invalid runId")
	}
	if len(s.Checks) == 0 || len(s.Checks) > 10 {
		return errors.New("invalid number of checks")
	}
	t, err := ParseTarget(s.Target.Raw)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if t.Host != s.Target.Host || t.IsIP != s.Target.IsIP {
		return errors.New("target host does not match raw target")
	}
	if _, err := s.Policy.Compile(); err != nil {
		return err
	}
	if s.MaxOutputBytes < 1 || s.MaxOutputBytes > 1<<20 {
		return errors.New("invalid maxOutputBytes")
	}
	if s.SettleMS < 0 || s.SettleMS > 30000 {
		return errors.New("invalid settleMs")
	}
	if _, err := ParseTrustedCAs(s.TrustedCAs); err != nil {
		return fmt.Errorf("trustedCas: %w", err)
	}
	ids := map[string]bool{}
	for _, c := range s.Checks {
		entry, ok := catalogEntry(c.Method)
		if !ok {
			return fmt.Errorf("method %q not in catalog", c.Method)
		}
		if ids[c.ID] || c.ID == "" {
			return errors.New("duplicate or empty check id")
		}
		ids[c.ID] = true
		if c.TimeoutMS < 100 || c.TimeoutMS > 60000 {
			return fmt.Errorf("check %s: invalid timeout", c.ID)
		}
		if entry.RequiresPort != (c.Port != 0) || (c.Port != 0 && ValidatePort(c.Port) != nil) {
			return fmt.Errorf("check %s: invalid port", c.ID)
		}
		if entry.HostnameOnly && s.Target.IsIP {
			return fmt.Errorf("check %s: hostname required", c.ID)
		}
		switch c.Method {
		case MethodHTTP, MethodHTTPS:
			if c.HTTP == nil || (c.HTTP.Method != "GET" && c.HTTP.Method != "HEAD") || ValidatePath(c.HTTP.Path) != nil ||
				(c.HTTP.IgnoreTLSErrors && c.Method != MethodHTTPS) {
				return fmt.Errorf("check %s: invalid http options", c.ID)
			}
		case MethodDNS:
			if c.DNS == nil || (c.DNS.Family != "ip" && c.DNS.Family != "ip4" && c.DNS.Family != "ip6") {
				return fmt.Errorf("check %s: invalid dns options", c.ID)
			}
		case MethodUDP:
			if c.UDP == nil || !validUDPProtocol(c.UDP.Protocol) {
				return fmt.Errorf("check %s: invalid udp options", c.ID)
			}
		case MethodPing:
			if c.Ping == nil || c.Ping.Count < 1 || c.Ping.Count > MaxPingCount {
				return fmt.Errorf("check %s: invalid ping options", c.ID)
			}
		case MethodTraceroute:
			if c.Traceroute == nil || c.Traceroute.MaxHops < 1 || c.Traceroute.MaxHops > MaxTracerouteHops {
				return fmt.Errorf("check %s: invalid traceroute options", c.ID)
			}
		}
	}
	return nil
}
