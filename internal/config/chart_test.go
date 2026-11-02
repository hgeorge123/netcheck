package config

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// TestChartRenderedConfig keeps the Helm chart and the strict config loader
// in sync. `make helm-lint` renders the ConfigMap and sets the variable; it is
// skipped otherwise because it needs helm.
func TestChartRenderedConfig(t *testing.T) {
	path := os.Getenv("NETCHECK_RENDERED_CONFIGMAP")
	if path == "" {
		t.Skip("NETCHECK_RENDERED_CONFIGMAP not set (run via make helm-lint)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(b, &cm); err != nil {
		t.Fatalf("rendered ConfigMap is not valid YAML: %v", err)
	}
	raw, ok := cm.Data["config.yaml"]
	if !ok {
		t.Fatal("config.yaml key missing")
	}
	cfg, err := Parse([]byte(raw), func(k string) string {
		if k == "POD_NAMESPACE" {
			return "netcheck"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("chart renders a config the application rejects: %v\n%s", err, raw)
	}
	if cfg.NamespaceScope.Mode == "" || cfg.Probe.Image == "" || cfg.WebDir != "/app/web" || cfg.Database.Path != "/data/netcheck.db" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}
