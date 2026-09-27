package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/google/ax/internal/store"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/protobuf/proto"
)

func TestStaleStatusCannotEraseDeleteMarkOrDesiredSpec(t *testing.T) {
	s := NewStore()
	ctx := context.Background()
	task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Image: "old"}}
	if err := s.SaveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	task.Spec.Image = "new"
	if err := s.SaveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	stale := &v1alpha1.TaskStatus{Phase: "Running", WorkerIp: "stale-worker"}
	if err := s.UpdateTaskStatus(ctx, "", "task", stale); err != nil {
		t.Fatal(err)
	}
	stale.Phase = "external-mutation"
	stored, err := s.GetTask(ctx, "default", "task")
	if err != nil || stored.Spec.Image != "new" || stored.Status.Phase != "Running" {
		t.Fatalf("status mutation lost desired spec or retained caller alias: %v, %v", stored, err)
	}
	if err := s.MarkTaskDeleting(ctx, "", "task"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTaskStatus(ctx, "", "task", &v1alpha1.TaskStatus{Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	stored, err = s.GetTask(ctx, "default", "task")
	if err != nil || stored.Status.Phase != v1alpha1.PhaseTerminating || stored.Spec.Image != "new" {
		t.Fatalf("late status erased persisted deletion or configuration: %v, %v", stored, err)
	}
}

func TestSaveTaskCannotClearPersistedDeleteMark(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	original := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Image: "keep"}}
	if err := s.SaveTask(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkTaskDeleting(ctx, "default", "task"); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetTask(ctx, "default", "task")
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"", "Pending", "Running", "Suspended", v1alpha1.PhaseTerminating} {
		t.Run("incoming-"+phase, func(t *testing.T) {
			stale := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Image: "overwrite"}}
			if phase != "" {
				stale.Status = &v1alpha1.TaskStatus{Phase: phase}
			}
			if err := s.SaveTask(ctx, stale); !errors.Is(err, store.ErrTaskTerminating) {
				t.Fatalf("save accepted persisted deletion: %v", err)
			}
			after, err := s.GetTask(ctx, "default", "task")
			if err != nil || !proto.Equal(before, after) {
				t.Fatalf("rejected save mutated task: %v, %v", after, err)
			}
		})
	}
}

func TestSaveTaskAndDeleteMarkAreSerialized(t *testing.T) {
	for range 100 {
		s := NewStore()
		ctx := context.Background()
		initial := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}}
		if err := s.SaveTask(ctx, initial); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		saved, marked := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			saved <- s.SaveTask(ctx, &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Suspend: false}, Status: &v1alpha1.TaskStatus{Phase: "Running"}})
		}()
		go func() { <-start; marked <- s.MarkTaskDeleting(ctx, "default", "task") }()
		close(start)
		if err := <-saved; err != nil && !errors.Is(err, store.ErrTaskTerminating) {
			t.Fatal(err)
		}
		if err := <-marked; err != nil {
			t.Fatal(err)
		}
		stored, err := s.GetTask(ctx, "default", "task")
		if err != nil || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating {
			t.Fatalf("save raced past deletion: %v %v", stored, err)
		}
	}
}

func TestDeleteQueueFailureIsVisibleAndPreservesMark(t *testing.T) {
	s := NewStore()
	s.tasks["default:task"] = &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task", Atespace: "default"}, Spec: &v1alpha1.TaskSpec{Image: "keep"}}
	for range cap(s.events) {
		s.events <- store.TaskEvent{}
	}
	if err := s.MarkTaskDeleting(context.Background(), "default", "task"); err == nil {
		t.Fatal("silently lost deletion event")
	}
	stored, err := s.GetTask(context.Background(), "default", "task")
	if err != nil || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating {
		t.Fatalf("failed publication lost delete mark: %v, %v", stored, err)
	}
	<-s.events
	if err := s.MarkTaskDeleting(context.Background(), "default", "task"); err != nil {
		t.Fatal(err)
	}
}
