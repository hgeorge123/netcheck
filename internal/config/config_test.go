package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

const digest = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/netcheck-probe@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func baseYAML(extra string) string {
	return `
environment: production
destinations:
  allowCidrs: [10.0.0.0/8]
  allowPorts: [{from: 80, to: 80}]
probe:
  image: ` + digest + "\n" + extra
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseDefaultsProduction(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML("")), env(map[string]string{"KUBERNETES_SERVICE_HOST": "172.20.0.1", "POD_NAMESPACE": "netcheck"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.NamespaceScope.Mode != ScopeAll || !cfg.Auth.CookieSecure || !cfg.Auth.BootstrapAdmin.ForcePasswordChange {
		t.Errorf("secure defaults not applied: %+v", cfg.Auth)
	}
	eff := cfg.EffectiveDestinations().DenyCIDRs
	if !slices.Contains(eff, "169.254.0.0/16") || !slices.Contains(eff, "172.20.0.1/32") {
		t.Errorf("builtin/kubernetes denies missing: %v", eff)
	}
	if cfg.DestinationsManagedBy != DestinationsManagedByUI || len(cfg.Destinations.DenyCIDRs) != 0 {
		t.Errorf("seed policy must not carry platform denies: %+v", cfg.Destinations)
	}
	ex := cfg.ExcludedNamespaces()
	for _, n := range []string{"kube-system", "kube-public", "kube-node-lease", "default", "netcheck"} {
		if !slices.Contains(ex, n) {
			t.Errorf("%s not excluded: %v", n, ex)
		}
	}
}

func TestPlatformProtectionsCanBeDisabled(t *testing.T) {
	open := strings.Replace(baseYAML("protectPlatformDestinations: false\n"), "allowCidrs: [10.0.0.0/8]", `allowCidrs: ["0.0.0.0/0", "::/0"]`, 1)
	cfg, err := Parse([]byte(open), env(map[string]string{"KUBERNETES_SERVICE_HOST": "172.20.0.1"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.EffectiveDestinations().DenyCIDRs) != 0 {
		t.Errorf("protections disabled but denies present: %v", cfg.PlatformDenies)
	}
	c, err := cfg.EffectiveDestinations().Compile()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"169.254.169.254", "172.20.0.1", "8.8.8.8"} {
		if err := c.CheckIP(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("%s denied with protections disabled: %v", ip, err)
		}
	}
}

func TestRejectsUnsafeConfig(t *testing.T) {
	prod := env(nil)
	cases := map[string]string{
		"tag image":            strings.Replace(baseYAML(""), digest, "repo/netcheck-probe:latest", 1),
		"unknown field":        baseYAML("shell: /bin/sh"),
		"insecure cookie prod": baseYAML("auth: {cookieSecure: false}"),
		"no forced change":     baseYAML("auth: {bootstrapAdmin: {forcePasswordChange: false}}"),
		"bad trusted proxy":    baseYAML("auth: {trustedProxyCidrs: [nope]}"),
		"lockout too lax":      baseYAML("auth: {maxFailedLogins: 1000}"),
		"list without ns":      baseYAML("namespaceScope: {mode: list}"),
		"list kube-system":     baseYAML("namespaceScope: {mode: list, namespaces: [kube-system]}"),
		"list default":         baseYAML("namespaceScope: {mode: list, namespaces: [default]}"),
		"all with list":        baseYAML("namespaceScope: {mode: all, namespaces: [payments]}"),
		"bad mode":             baseYAML("namespaceScope: {mode: everything}"),
		"bad exclude":          baseYAML("namespaceScope: {exclude: [Bad_NS]}"),
		"bad cidr":             strings.Replace(baseYAML(""), "10.0.0.0/8", "10.0.0.0/99", 1),
		"bad managedBy":        baseYAML("destinationsManagedBy: git"),
		"huge job":             baseYAML("limits: {maxJobSeconds: 3600}"),
		"root probe":           strings.Replace(baseYAML(""), "probe:\n", "probe:\n  runAsUser: 0\n", 1),
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y), prod); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	// Environment mismatch with NETCHECK_ENV is refused.
	if _, err := Parse([]byte(baseYAML("")), env(map[string]string{"NETCHECK_ENV": "development"})); err == nil {
		t.Error("environment mismatch accepted")
	}
}

func TestDevelopmentRelaxations(t *testing.T) {
	y := strings.Replace(baseYAML("auth: {cookieSecure: false, bootstrapAdmin: {forcePasswordChange: false}}"), "production", "development", 1)
	if _, err := Parse([]byte(y), env(map[string]string{"NETCHECK_ENV": "development"})); err != nil {
		t.Errorf("development relaxations rejected: %v", err)
	}
}

func TestListModeOwnNamespace(t *testing.T) {
	y := baseYAML("namespaceScope: {mode: list, namespaces: [payments, netcheck]}")
	if _, err := Parse([]byte(y), env(map[string]string{"POD_NAMESPACE": "netcheck"})); err == nil {
		t.Error("own namespace accepted as probe source")
	}
}
