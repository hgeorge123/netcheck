package auth

import (
	"context"
	"slices"
	"testing"
)

type staticSource []string

func (s staticSource) Available(context.Context) ([]string, error) {
	return slices.Clone([]string(s)), nil
}

func TestWebExclusionsOnlyRemove(t *testing.T) {
	w := NewWebExclusions(staticSource{"orders", "payments", "shipping"}, []string{"payments", "not-in-base"})
	got, _ := w.Available(context.Background())
	if !slices.Equal(got, []string{"orders", "shipping"}) {
		t.Errorf("Available = %v", got)
	}
	a := &Authorizer{Source: w}
	if ok, _ := a.CanRun(context.Background(), Identity{Role: RoleAdmin}, "payments"); ok {
		t.Error("admin can run in a web-excluded namespace")
	}
	w.Set(nil)
	if ok, _ := a.CanRun(context.Background(), Identity{Role: RoleAdmin}, "payments"); !ok {
		t.Error("namespace not available again after removing the exclusion")
	}
}
