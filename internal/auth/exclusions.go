package auth

import (
	"context"
	"slices"
	"sync"
)

// WebExclusions hides, on top of Base, the namespaces that administrators
// excluded in the web. It can only remove namespaces, never add them: the
// Helm exclusions and system namespaces are already absent from Base (and
// also enforced by admission control).
type WebExclusions struct {
	Base NamespaceSource

	mu    sync.RWMutex
	names map[string]bool
}

// NewWebExclusions wraps base with the given excluded names.
func NewWebExclusions(base NamespaceSource, names []string) *WebExclusions {
	w := &WebExclusions{Base: base}
	w.Set(names)
	return w
}

// Set replaces the excluded names (takes effect immediately).
func (w *WebExclusions) Set(names []string) {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	w.mu.Lock()
	w.names = m
	w.mu.Unlock()
}

// Excluded reports whether ns is excluded in the web.
func (w *WebExclusions) Excluded(ns string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.names[ns]
}

// Available implements NamespaceSource.
func (w *WebExclusions) Available(ctx context.Context) ([]string, error) {
	list, err := w.Base.Available(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list, w.Excluded), nil
}
