package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNamespaceExclusions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	ev := AuditEvent{ActorID: "u1", Action: "namespace.exclude", Outcome: "success"}
	for _, n := range []string{"payments", "orders"} {
		if err := s.AddNamespaceExclusion(ctx, NamespaceExclusion{Name: n, Reason: "pci", CreatedAt: now, CreatedBy: "admin"}, ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddNamespaceExclusion(ctx, NamespaceExclusion{Name: "orders", CreatedAt: now, CreatedBy: "admin"}, ev); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("duplicate: %v", err)
	}
	list, err := s.ListNamespaceExclusions(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "orders" || list[1].Reason != "pci" || !list[0].CreatedAt.Equal(now) {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.DeleteNamespaceExclusion(ctx, "orders", ev); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNamespaceExclusion(ctx, "orders", ev); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}
