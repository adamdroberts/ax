package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/ax/internal/controller"
	"github.com/google/ax/internal/server"
	"github.com/google/ax/internal/store"
	"github.com/google/ax/internal/store/memory"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gatewaySingleEventStore struct {
	store.Store
	cancel context.CancelFunc
}

type gatewayProcessOneStore struct {
	store.Store
	cancel context.CancelFunc
}

func (s *gatewayProcessOneStore) Subscribe(ctx context.Context, group, consumer string) (store.Subscription, error) {
	sub, err := s.Store.Subscribe(ctx, group, consumer)
	if err != nil {
		return nil, err
	}
	return &gatewayStopAfterAck{Subscription: sub, cancel: s.cancel}, nil
}

type gatewayStopAfterAck struct {
	store.Subscription
	cancel context.CancelFunc
}

func (s *gatewayStopAfterAck) Ack(ctx context.Context, ev store.TaskEvent) error {
	err := s.Subscription.Ack(ctx, ev)
	s.cancel()
	return err
}

func TestGatewayNarrowingAndDeletionReplaceExistingActorPolicy(t *testing.T) {
	for _, operation := range []string{"narrow", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mem := memory.NewStore()
			gw := &v1alpha1.Gateway{Metadata: &v1alpha1.ObjectMeta{Name: "gateway", Atespace: "tenant-a"}, Spec: &v1alpha1.GatewaySpec{Egress: &v1alpha1.EgressConfig{Allowlist: &v1alpha1.EgressAllowlist{Hosts: []*v1alpha1.HostRule{{Host: "*"}}}}}}
			if err := mem.SaveGateway(ctx, gw); err != nil {
				t.Fatal(err)
			}
			task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "running", Atespace: "tenant-a"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "gateway"}}, Status: &v1alpha1.TaskStatus{Phase: "Running", Conditions: []*v1alpha1.Condition{{Type: "WorkspaceReady", Status: "True"}}}}
			if err := mem.SaveTask(ctx, task); err != nil {
				t.Fatal(err)
			}
			sub, err := mem.Subscribe(ctx, "drain", "drain")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sub.Next(ctx); err != nil {
				t.Fatal(err)
			}
			sub.Close() // Only the new Gateway event should drive reconciliation.
			api := server.NewServer(mem)
			if operation == "narrow" {
				gw.Spec.Egress.Allowlist.Hosts = nil
				if _, err := api.UpdateGateway(ctx, &v1alpha1.UpdateGatewayRequest{Gateway: gw}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := api.DeleteGateway(ctx, &v1alpha1.DeleteGatewayRequest{Atespace: "tenant-a", Name: "gateway"}); err != nil {
					t.Fatal(err)
				}
			}
			control := &mockControlServer{policyError: status.Error(codes.AlreadyExists, "existing broad policy"), existingPolicy: &ateapipb.EgressPolicy{Metadata: &ateapipb.ResourceMetadata{Uid: "policy-id", Version: 3}, Rules: []*ateapipb.EgressRule{{Hostnames: &ateapipb.HostnameRule{Patterns: []string{"*.example.com"}}}}}}
			reconciler := controller.NewTaskReconciler(securityTestClient(t, control), "default-template", "ax-system")
			reconciler.SecretResolver = noSecrets
			worker := controller.NewWorker(&gatewayProcessOneStore{Store: mem, cancel: cancel}, reconciler, "test", "test")
			if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if len(control.updatedPolicies) != 1 || len(control.updatedPolicies[0].Rules) != 0 || control.updatedPolicies[0].Metadata.Version != 3 {
				t.Fatalf("stale broad policy was not replaced: %v", control.updatedPolicies)
			}
			if len(control.resumedActors) != 1 {
				t.Fatalf("expected policy admission followed by normal task reconciliation: %v", control.events)
			}
		})
	}
}

func (s *gatewaySingleEventStore) Subscribe(context.Context, string, string) (store.Subscription, error) {
	return &gatewaySingleEventSubscription{cancel: s.cancel}, nil
}

type gatewaySingleEventSubscription struct {
	cancel    context.CancelFunc
	delivered bool
}

func (s *gatewaySingleEventSubscription) Next(ctx context.Context) (store.TaskEvent, error) {
	if s.delivered {
		return store.TaskEvent{}, ctx.Err()
	}
	s.delivered = true
	return store.TaskEvent{Atespace: "default", Name: "terminating", Action: "reconcile"}, nil
}
func (s *gatewaySingleEventSubscription) Ack(context.Context, store.TaskEvent) error {
	s.cancel()
	return nil
}
func (*gatewaySingleEventSubscription) Close() error { return nil }

func TestGatewayReconcileQueuedBeforeDeletionCannotResumeTerminatingTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := memory.NewStore()
	task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "terminating"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "gateway"}}}
	if err := mem.SaveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if err := mem.MarkTaskDeleting(ctx, "default", "terminating"); err != nil {
		t.Fatal(err)
	}
	control := &mockControlServer{}
	reconciler := controller.NewTaskReconciler(securityTestClient(t, control), "default-template", "ax-system")
	reconciler.SecretResolver = noSecrets
	worker := controller.NewWorker(&gatewaySingleEventStore{Store: mem, cancel: cancel}, reconciler, "test", "test")
	if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(control.resumedActors) != 0 || len(control.createdPolicies) != 0 || len(control.deletedActors) != 1 {
		t.Fatalf("stale reconcile overrode deletion: resumes=%v policies=%v deletes=%v", control.resumedActors, control.createdPolicies, control.deletedActors)
	}
	if _, err := mem.GetTask(context.Background(), "default", "terminating"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("terminating task was not removed: %v", err)
	}
}
