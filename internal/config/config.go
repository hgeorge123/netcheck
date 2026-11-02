// Package config loads and validates the protected NetCheck configuration.
// Unsafe combinations fail at start-up instead of being silently accepted.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/hgeorge123/netcheck/internal/probes"
)

// Environments.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Namespace scope modes.
const (
	ScopeAll  = "all"
	ScopeList = "list"
)

// SystemNamespaces can never be probe sources (also enforced by the
// admission policy).
var SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "default"}

// Config is the full application configuration.
type Config struct {
	Environment        string                   `json:"environment"`
	ClusterID          string                   `json:"clusterId"`
	Listen             string                   `json:"listen"`
	WebDir             string                   `json:"webDir"`
	Database           Database                 `json:"database"`
	Auth               Auth                     `json:"auth"`
	NamespaceScope     NamespaceScope           `json:"namespaceScope"`
	Destinations       probes.DestinationPolicy `json:"destinations"`
	KubeAPIServerCIDRs []string                 `json:"kubeApiServerCidrs"`
	// ProtectPlatformDestinations adds probes.BuiltinDenyCIDRs (metadata,
	// loopback, link-local, multicast) and the API server addresses to the
	// denied destinations. It can be disabled, but should not be.
	ProtectPlatformDestinations bool `json:"protectPlatformDestinations"`
	// DestinationsManagedBy is "ui" (Destinations only seed the policy stored
	// in the database, administrators edit it in the web) or "helm" (the
	// configuration is authoritative and the web is read-only).
	DestinationsManagedBy string    `json:"destinationsManagedBy"`
	Limits                Limits    `json:"limits"`
	Probe                 Probe     `json:"probe"`
	Retention             Retention `json:"retention"`
	NetworkPolicyRead     bool      `json:"networkPolicyRead"`

	// OwnNamespace is where NetCheck runs (POD_NAMESPACE); always excluded.
	OwnNamespace string `json:"-"`
	// PlatformDenies are the destinations always denied on top of any policy
	// (builtin ranges and API server addresses); empty when
	// ProtectPlatformDestinations is false. Computed by Parse.
	PlatformDenies []string `json:"-"`
}

// Values of DestinationsManagedBy.
const (
	DestinationsManagedByUI   = "ui"
	DestinationsManagedByHelm = "helm"
)

// Database configures SQLite.
type Database struct {
	Path string `json:"path"`
	// WAL must be disabled on storage that does not support shared memory
	// locking semantics (e.g. network filesystems).
	WAL bool `json:"wal"`
}

// Auth configures local accounts.
type Auth struct {
	SessionIdleMinutes    int            `json:"sessionIdleMinutes"`
	SessionMaxHours       int            `json:"sessionMaxHours"`
	MaxFailedLogins       int            `json:"maxFailedLogins"`
	LockoutMinutes        int            `json:"lockoutMinutes"`
	LoginAttemptsPerIPMin int            `json:"loginAttemptsPerIpPerMinute"`
	CookieSecure          bool           `json:"cookieSecure"`
	TrustedProxyCIDRs     []string       `json:"trustedProxyCidrs"`
	BootstrapAdmin        BootstrapAdmin `json:"bootstrapAdmin"`
}

// BootstrapAdmin is the initial administrator. The password comes from the
// NETCHECK_BOOTSTRAP_ADMIN_PASSWORD environment variable (Kubernetes Secret).
type BootstrapAdmin struct {
	Username            string `json:"username"`
	ForcePasswordChange bool   `json:"forcePasswordChange"`
}

// NamespaceScope selects which namespaces probes may run in.
type NamespaceScope struct {
	Mode       string   `json:"mode"`
	Namespaces []string `json:"namespaces"`
	Exclude    []string `json:"exclude"`
}

// Limits bounds resource usage.
type Limits struct {
	MaxChecksPerRun            int `json:"maxChecksPerRun"`
	DefaultCheckTimeoutSeconds int `json:"defaultCheckTimeoutSeconds"`
	MaxCheckTimeoutSeconds     int `json:"maxCheckTimeoutSeconds"`
	MaxJobSeconds              int `json:"maxJobSeconds"`
	MaxOutputBytes             int `json:"maxOutputBytes"`
	MaxConcurrentPerNamespace  int `json:"maxConcurrentPerNamespace"`
	MaxConcurrentGlobal        int `json:"maxConcurrentGlobal"`
}

// Probe configures the ephemeral probe Job template.
type Probe struct {
	Image                   string `json:"image"`
	ServiceAccountName      string `json:"serviceAccountName"`
	RunAsUser               int64  `json:"runAsUser"`
	CPURequest              string `json:"cpuRequest"`
	CPULimit                string `json:"cpuLimit"`
	MemoryRequest           string `json:"memoryRequest"`
	MemoryLimit             string `json:"memoryLimit"`
	EphemeralStorageLimit   string `json:"ephemeralStorageLimit"`
	TTLSecondsAfterFinished int32  `json:"ttlSecondsAfterFinished"`
	// SettleSeconds delays checks so the CNI can program policies for the new
	// Pod (relevant for AWS VPC CNI standard enforcing mode).
	SettleSeconds int `json:"settleSeconds"`
	// NodeSelector places probes (e.g. kubernetes.io/os=linux on mixed clusters).
	NodeSelector map[string]string `json:"nodeSelector"`
}

// Retention configures periodic purge of history.
type Retention struct {
	OutputDays   int `json:"outputDays"`
	MetadataDays int `json:"metadataDays"`
}

var (
	dnsLabel       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	digestImageRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)
)

// Defaults returns a configuration with the default limits.
func Defaults() Config {
	return Config{
		Environment: EnvProduction,
		ClusterID:   "default",
		Listen:      ":8080",
		Database:    Database{Path: "/data/netcheck.db", WAL: true},
		Auth: Auth{
			SessionIdleMinutes:    60,
			SessionMaxHours:       12,
			MaxFailedLogins:       5,
			LockoutMinutes:        15,
			LoginAttemptsPerIPMin: 20,
			CookieSecure:          true,
			BootstrapAdmin:        BootstrapAdmin{Username: "admin", ForcePasswordChange: true},
		},
		NamespaceScope:              NamespaceScope{Mode: ScopeAll},
		ProtectPlatformDestinations: true,
		DestinationsManagedBy:       DestinationsManagedByUI,
		Limits: Limits{
			MaxChecksPerRun:            6,
			DefaultCheckTimeoutSeconds: 5,
			MaxCheckTimeoutSeconds:     10,
			MaxJobSeconds:              90,
			MaxOutputBytes:             64 << 10,
			MaxConcurrentPerNamespace:  3,
			MaxConcurrentGlobal:        10,
		},
		Probe: Probe{
			ServiceAccountName:      "netcheck-probe",
			RunAsUser:               65532,
			CPURequest:              "50m",
			CPULimit:                "200m",
			MemoryRequest:           "32Mi",
			MemoryLimit:             "64Mi",
			EphemeralStorageLimit:   "16Mi",
			TTLSecondsAfterFinished: 300,
		},
		Retention:         Retention{OutputDays: 30, MetadataDays: 90},
		NetworkPolicyRead: true,
	}
}

// Load reads path (YAML or JSON) over Defaults and validates the result.
// getenv is injected for tests.
func Load(path string, getenv func(string) string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(b, getenv)
}

// Parse decodes and validates raw configuration.
func Parse(b []byte, getenv func(string) string) (Config, error) {
	cfg := Defaults()
	if err := yaml.UnmarshalStrict(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.OwnNamespace = getenv("POD_NAMESPACE")
	if err := cfg.validate(getenv); err != nil {
		return Config{}, err
	}
	if !cfg.ProtectPlatformDestinations {
		return cfg, nil
	}
	cfg.PlatformDenies = append(append([]string(nil), probes.BuiltinDenyCIDRs...), cfg.KubeAPIServerCIDRs...)
	if host := getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		if a, err := netip.ParseAddr(host); err == nil {
			cfg.PlatformDenies = append(cfg.PlatformDenies, netip.PrefixFrom(a, a.BitLen()).String())
		}
	}
	return cfg, nil
}

// EffectiveDestinations is the configured policy with the platform denies.
func (c Config) EffectiveDestinations() probes.DestinationPolicy {
	return c.Destinations.WithDenies(c.PlatformDenies...)
}

// ExcludedNamespaces returns system, own and configured exclusions.
func (c Config) ExcludedNamespaces() []string {
	out := append([]string(nil), SystemNamespaces...)
	if c.OwnNamespace != "" {
		out = append(out, c.OwnNamespace)
	}
	for _, n := range c.NamespaceScope.Exclude {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func (c *Config) validate(getenv func(string) string) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Environment != EnvDevelopment && c.Environment != EnvProduction {
		add("environment must be %q or %q", EnvDevelopment, EnvProduction)
	}
	if c.Environment != getenv("NETCHECK_ENV") && getenv("NETCHECK_ENV") != "" {
		add("environment %q does not match NETCHECK_ENV=%q", c.Environment, getenv("NETCHECK_ENV"))
	}
	a := c.Auth
	switch {
	case a.SessionIdleMinutes < 5 || a.SessionIdleMinutes > 24*60:
		add("auth.sessionIdleMinutes must be 5-1440")
	case a.SessionMaxHours < 1 || a.SessionMaxHours > 168:
		add("auth.sessionMaxHours must be 1-168")
	case a.MaxFailedLogins < 3 || a.MaxFailedLogins > 20:
		add("auth.maxFailedLogins must be 3-20")
	case a.LockoutMinutes < 1 || a.LockoutMinutes > 24*60:
		add("auth.lockoutMinutes must be 1-1440")
	case a.LoginAttemptsPerIPMin < 1 || a.LoginAttemptsPerIPMin > 1000:
		add("auth.loginAttemptsPerIpPerMinute must be 1-1000")
	}
	// Relaxations are only possible in development, never in production.
	if c.Environment != EnvDevelopment {
		if !a.CookieSecure {
			add("auth.cookieSecure=false is only allowed in development")
		}
		if !a.BootstrapAdmin.ForcePasswordChange {
			add("auth.bootstrapAdmin.forcePasswordChange=false is only allowed in development")
		}
	}
	for _, s := range a.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			add("auth.trustedProxyCidrs: invalid CIDR %q", s)
		}
	}
	if c.Database.Path == "" {
		add("database.path is required")
	}

	ns := c.NamespaceScope
	switch ns.Mode {
	case ScopeAll:
		if len(ns.Namespaces) > 0 {
			add("namespaceScope.namespaces must be empty in mode %q (use exclude)", ScopeAll)
		}
	case ScopeList:
		if len(ns.Namespaces) == 0 {
			add("namespaceScope.namespaces must list at least one namespace in mode %q", ScopeList)
		}
	default:
		add("namespaceScope.mode must be %q or %q", ScopeAll, ScopeList)
	}
	seen := map[string]bool{}
	for _, n := range append(append([]string(nil), ns.Namespaces...), ns.Exclude...) {
		if !dnsLabel.MatchString(n) {
			add("namespace %q is not a valid DNS label", n)
		}
	}
	for _, n := range ns.Namespaces {
		switch {
		case slices.Contains(SystemNamespaces, n) || n == c.OwnNamespace:
			add("namespace %q is not allowed as probe source", n)
		case seen[n]:
			add("namespace %q configured twice", n)
		}
		seen[n] = true
	}

	if c.DestinationsManagedBy != DestinationsManagedByUI && c.DestinationsManagedBy != DestinationsManagedByHelm {
		add("destinationsManagedBy must be ui or helm")
	}
	if !digestImageRef.MatchString(c.Probe.Image) {
		add("probe.image must be pinned by digest (repo@sha256:<64 hex>)")
	}
	if !dnsLabel.MatchString(c.Probe.ServiceAccountName) {
		add("probe.serviceAccountName is invalid")
	}
	if c.Probe.RunAsUser < 1 {
		add("probe.runAsUser must be a non-root UID")
	}
	if c.Probe.SettleSeconds < 0 || c.Probe.SettleSeconds > 15 {
		add("probe.settleSeconds must be between 0 and 15")
	}
	l := c.Limits
	switch {
	case l.MaxChecksPerRun < 1 || l.MaxChecksPerRun > 10:
		add("limits.maxChecksPerRun must be 1-10")
	case l.MaxCheckTimeoutSeconds < 1 || l.MaxCheckTimeoutSeconds > 60:
		add("limits.maxCheckTimeoutSeconds must be 1-60")
	case l.DefaultCheckTimeoutSeconds < 1 || l.DefaultCheckTimeoutSeconds > l.MaxCheckTimeoutSeconds:
		add("limits.defaultCheckTimeoutSeconds must be 1-maxCheckTimeoutSeconds")
	case l.MaxJobSeconds < 10 || l.MaxJobSeconds > 300:
		add("limits.maxJobSeconds must be 10-300")
	case l.MaxOutputBytes < 1024 || l.MaxOutputBytes > 1<<20:
		add("limits.maxOutputBytes must be 1KiB-1MiB")
	case l.MaxConcurrentPerNamespace < 1 || l.MaxConcurrentGlobal < l.MaxConcurrentPerNamespace:
		add("limits concurrency values are inconsistent")
	}
	if _, err := c.Destinations.Compile(); err != nil {
		add("destinations: %v", err)
	}
	for _, s := range c.KubeAPIServerCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			add("kubeApiServerCidrs: invalid CIDR %q", s)
		}
	}
	if c.Retention.OutputDays < 1 || c.Retention.MetadataDays < c.Retention.OutputDays {
		add("retention: outputDays must be >= 1 and metadataDays >= outputDays")
	}
	return errors.Join(errs...)
}

// TrustedProxies parses auth.trustedProxyCidrs (already validated).
func (c Config) TrustedProxies() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.Auth.TrustedProxyCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// ProbeLimits converts limits into the probes package representation.
func (c Config) ProbeLimits() probes.Limits {
	return probes.Limits{
		MaxChecks:           c.Limits.MaxChecksPerRun,
		DefaultCheckTimeout: time.Duration(c.Limits.DefaultCheckTimeoutSeconds) * time.Second,
		MaxCheckTimeout:     time.Duration(c.Limits.MaxCheckTimeoutSeconds) * time.Second,
		MaxJobDuration:      time.Duration(c.Limits.MaxJobSeconds) * time.Second,
		MaxOutputBytes:      c.Limits.MaxOutputBytes,
		Settle:              time.Duration(c.Probe.SettleSeconds) * time.Second,
	}
}
