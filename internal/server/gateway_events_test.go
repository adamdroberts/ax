package server_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/ax/internal/server"
	"github.com/google/ax/internal/store"
	"github.com/google/ax/internal/store/memory"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func gatewayEvents(t *testing.T, sub store.Subscription, count int) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	seen := make(map[string]bool)
	for range count {
		event, err := sub.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		key := event.Atespace + "/" + event.Name
		if event.Action != "reconcile" || seen[key] {
			t.Fatalf("unexpected or duplicate event: %v", event)
		}
		seen[key] = true
	}
	return seen
}

func noGatewayEvents(t *testing.T, sub store.Subscription) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if event, err := sub.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected extra event: %v, %v", event, err)
	}
}

func TestGatewayChangesEnqueueEveryScopedBindingWithoutChangingTasks(t *testing.T) {
	ctx := context.Background()
	mem := memory.NewStore()
	srv := server.NewServer(mem)
	sub, err := mem.Subscribe(ctx, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	var original []*v1alpha1.Task
	want := make(map[string]bool)
	// Exceeds the old ListTasks default limit. Include a suspended task: policy
	// updates must reach it before a later router-driven resume, too.
	for i := range 83 {
		task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: fmt.Sprintf("task-%d", i), Atespace: "tenant-a"},
			Spec:   &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "shared"}, Image: "original", Suspend: i == 0},
			Status: &v1alpha1.TaskStatus{Phase: "Running", WorkerIp: "original-worker"}}
		if err := mem.SaveTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		original = append(original, proto.Clone(task).(*v1alpha1.Task))
		want["tenant-a/"+task.Metadata.Name] = true
	}
	for _, task := range []*v1alpha1.Task{
		{Metadata: &v1alpha1.ObjectMeta{Name: "other-tenant", Atespace: "tenant-b"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "shared"}}},
		{Metadata: &v1alpha1.ObjectMeta{Name: "other-gateway", Atespace: "tenant-a"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "different"}}},
		{Metadata: &v1alpha1.ObjectMeta{Name: "unbound", Atespace: "tenant-a"}},
		{Metadata: &v1alpha1.ObjectMeta{Name: "terminating", Atespace: "tenant-a"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "shared"}}, Status: &v1alpha1.TaskStatus{Phase: v1alpha1.PhaseTerminating}},
	} {
		if err := mem.SaveTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		original = append(original, proto.Clone(task).(*v1alpha1.Task))
	}
	gatewayEvents(t, sub, len(original)) // Ignore initial task creation events.
	if err := mem.SaveGateway(ctx, &v1alpha1.Gateway{Metadata: &v1alpha1.ObjectMeta{Name: "shared", Atespace: "tenant-a"},
		Spec: &v1alpha1.GatewaySpec{Egress: &v1alpha1.EgressConfig{Allowlist: &v1alpha1.EgressAllowlist{Hosts: []*v1alpha1.HostRule{{Host: "*"}}}}}}); err != nil {
		t.Fatal(err)
	}
	narrow := &v1alpha1.Gateway{Metadata: &v1alpha1.ObjectMeta{Name: "shared", Atespace: "tenant-a"},
		Spec: &v1alpha1.GatewaySpec{Egress: &v1alpha1.EgressConfig{Allowlist: &v1alpha1.EgressAllowlist{}}}}
	for _, operation := range []string{"narrow", "delete", "retry-delete"} {
		t.Run(operation, func(t *testing.T) {
			if operation == "narrow" {
				if _, err := srv.UpdateGateway(ctx, &v1alpha1.UpdateGatewayRequest{Gateway: narrow}); err != nil {
					t.Fatal(err)
				}
				stored, err := mem.GetGateway(ctx, "tenant-a", "shared")
				if err != nil || len(stored.GetSpec().GetEgress().GetAllowlist().GetHosts()) != 0 {
					t.Fatalf("narrow policy was not saved: %v, %v", stored, err)
				}
			} else {
				if _, err := srv.DeleteGateway(ctx, &v1alpha1.DeleteGatewayRequest{Atespace: "tenant-a", Name: "shared"}); err != nil {
					t.Fatal(err)
				}
				if _, err := mem.GetGateway(ctx, "tenant-a", "shared"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("gateway remained after deletion: %v", err)
				}
			}
			seen := gatewayEvents(t, sub, len(want))
			for key := range want {
				if !seen[key] {
					t.Fatalf("missing binding %s", key)
				}
			}
			noGatewayEvents(t, sub)
			for _, before := range original {
				after, err := mem.GetTask(ctx, before.Metadata.Atespace, before.Metadata.Name)
				if err != nil || !proto.Equal(before, after) {
					t.Fatalf("task was changed by fanout: %v, %v", after, err)
				}
			}
		})
	}
}

type failingGatewayQueue struct {
	store.Store
	fail  bool
	calls int
}

func (s *failingGatewayQueue) EnqueueGatewayTasks(ctx context.Context, atespace, name string) error {
	s.calls++
	if s.fail {
		return errors.New("queue unavailable")
	}
	return s.Store.EnqueueGatewayTasks(ctx, atespace, name)
}

func TestGatewayPublicationFailureIsVisibleAndDeletionCanBeRetried(t *testing.T) {
	ctx := context.Background()
	mem := memory.NewStore()
	queue := &failingGatewayQueue{Store: mem, fail: true}
	srv := server.NewServer(queue)
	gw := &v1alpha1.Gateway{Metadata: &v1alpha1.ObjectMeta{Name: "gateway"}}
	if _, err := srv.UpdateGateway(ctx, &v1alpha1.UpdateGatewayRequest{Gateway: gw}); status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "gateway saved") {
		t.Fatalf("save/publication split was hidden: %v", err)
	}
	if _, err := mem.GetGateway(ctx, "default", "gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.DeleteGateway(ctx, &v1alpha1.DeleteGatewayRequest{Name: "gateway"}); status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "gateway deleted") {
		t.Fatalf("deletion/publication split was hidden: %v", err)
	}
	if _, err := mem.GetGateway(ctx, "default", "gateway"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete did not persist: %v", err)
	}
	queue.fail = false
	if _, err := srv.DeleteGateway(ctx, &v1alpha1.DeleteGatewayRequest{Name: "gateway"}); err != nil || queue.calls != 3 {
		t.Fatalf("already-deleted gateway cannot retry fanout: %v, %d", err, queue.calls)
	}
}
