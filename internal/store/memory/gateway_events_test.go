package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/ax/internal/store"
	"github.com/google/ax/pkg/apis/v1alpha1"
)

func TestGatewayFanoutExceedsQueueCapacityWithoutDroppingEvents(t *testing.T) {
	s := NewStore()
	const total = 1237
	for i := range total {
		name := fmt.Sprintf("task-%d", i)
		s.tasks[taskKey("default", name)] = &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: name, Atespace: "default"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "gateway"}}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.EnqueueGatewayTasks(ctx, "", "gateway") }()
	sub, _ := s.Subscribe(ctx, "test", "test")
	seen := make(map[string]bool)
	for range total {
		ev, err := sub.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Atespace != "default" || ev.Action != "reconcile" || seen[ev.Name] {
			t.Fatalf("unexpected event: %v", ev)
		}
		seen[ev.Name] = true
		// A blocked publisher must not hold the store lock needed by consumers.
		if _, err := s.GetTask(ctx, "default", ev.Name); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayFanoutFullQueueReturnsCancellation(t *testing.T) {
	s := NewStore()
	s.tasks["default:task"] = &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task", Atespace: "default"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "gateway"}}}
	for range cap(s.events) {
		s.events <- store.TaskEvent{Name: "already-queued"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := s.EnqueueGatewayTasks(ctx, "default", "gateway"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full queue silently discarded an event: %v", err)
	}
	if len(s.events) != cap(s.events) || len(s.tasks) != 1 {
		t.Fatal("publication failure changed stored data")
	}
}
