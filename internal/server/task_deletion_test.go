package server_test

import (
	"context"
	"testing"

	"github.com/google/ax/internal/server"
	"github.com/google/ax/internal/store"
	"github.com/google/ax/internal/store/memory"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Interleave deletion after the API reads a task but before it saves its copy.
type deleteBeforeTaskSave struct{ store.Store }

func (s *deleteBeforeTaskSave) SaveTask(ctx context.Context, task *v1alpha1.Task) error {
	if err := s.Store.MarkTaskDeleting(ctx, task.Metadata.Atespace, task.Metadata.Name); err != nil {
		return err
	}
	return s.Store.SaveTask(ctx, task)
}

func TestTaskMutationsCannotCancelDeletion(t *testing.T) {
	for _, interleave := range []bool{false, true} {
		for _, operation := range []string{"update", "suspend", "resume"} {
			name := operation + "/already-terminating"
			if interleave {
				name = operation + "/deletion-before-save"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				mem := memory.NewStore()
				t.Cleanup(func() { _ = mem.Close() })
				original := &v1alpha1.Task{
					Metadata: &v1alpha1.ObjectMeta{Name: "task", Atespace: "default"},
					Spec:     &v1alpha1.TaskSpec{Image: "original-image"},
					Status:   &v1alpha1.TaskStatus{Phase: "Running"},
				}
				if err := mem.SaveTask(ctx, original); err != nil {
					t.Fatal(err)
				}
				var target store.Store = mem
				if interleave {
					target = &deleteBeforeTaskSave{Store: mem}
				} else if err := mem.MarkTaskDeleting(ctx, "default", "task"); err != nil {
					t.Fatal(err)
				}
				srv := server.NewServer(target)
				var result *v1alpha1.Task
				var err error
				switch operation {
				case "update":
					// Omitted status used to default back to Pending.
					result, err = srv.UpdateTask(ctx, &v1alpha1.UpdateTaskRequest{Task: &v1alpha1.Task{
						Metadata: proto.Clone(original.Metadata).(*v1alpha1.ObjectMeta),
						Spec:     &v1alpha1.TaskSpec{Image: "replacement-image"},
					}})
				case "suspend":
					result, err = srv.SuspendTask(ctx, &v1alpha1.SuspendTaskRequest{Name: "task"})
				case "resume":
					result, err = srv.ResumeTask(ctx, &v1alpha1.ResumeTaskRequest{Name: "task"})
				}
				if result != nil || status.Code(err) != codes.FailedPrecondition {
					t.Fatalf("mutation reported success or wrong error: result=%v err=%v", result, err)
				}
				stored, err := mem.GetTask(ctx, "default", "task")
				if err != nil || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating || !proto.Equal(stored.GetSpec(), original.Spec) {
					t.Fatalf("mutation altered terminating task: %v, %v", stored, err)
				}
			})
		}
	}
}
