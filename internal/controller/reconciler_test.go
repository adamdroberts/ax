// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/ax/internal/controller"
	"github.com/google/ax/internal/substrate"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type mockControlServer struct {
	ateapipb.UnimplementedControlServer
	workerIP         string
	createdAtespaces []string
	createdActors    []string
	resumedActors    []string
	suspendedActors  []string
	createdPolicies  []string
	deletedActors    []string
	actorTemplates   map[string]bool
	deletedTemplates []string
	policyError      error
	atespaceError    error
	actorError       error
	suspendError     error
	policyRequests   []*ateapipb.EgressPolicy
	events           []string
	existingPolicy   *ateapipb.EgressPolicy
	policyReadError  error
	updatedPolicies  []*ateapipb.EgressPolicy
}

// noSecrets is a SecretResolver for tests: it never finds a key and never touches a cluster.
func noSecrets(context.Context, string, string, string) (string, error) {
	return "", nil
}

func (m *mockControlServer) CreateAtespace(ctx context.Context, req *ateapipb.CreateAtespaceRequest) (*ateapipb.Atespace, error) {
	name := ""
	if req.Atespace != nil && req.Atespace.Metadata != nil {
		name = req.Atespace.Metadata.Name
	}
	m.createdAtespaces = append(m.createdAtespaces, name)
	if m.atespaceError != nil {
		return nil, m.atespaceError
	}
	return &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: name}}, nil
}

func (m *mockControlServer) CreateActor(ctx context.Context, req *ateapipb.CreateActorRequest) (*ateapipb.Actor, error) {
	name := ""
	if req.Actor != nil && req.Actor.Metadata != nil {
		name = req.Actor.Metadata.Name
	}
	m.createdActors = append(m.createdActors, name)
	if m.actorError != nil {
		return nil, m.actorError
	}
	return &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Name: name},
		Status: &ateapipb.ActorStatus{
			State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED,
		},
	}, nil
}

func (m *mockControlServer) ResumeActor(ctx context.Context, req *ateapipb.ResumeActorRequest) (*ateapipb.ResumeActorResponse, error) {
	name := ""
	if req.Actor != nil {
		name = req.Actor.Name
	}
	m.resumedActors = append(m.resumedActors, name)
	m.events = append(m.events, "resume")
	wIP := "10.244.1.42"
	if m.workerIP != "" {
		wIP = m.workerIP
	}
	return &ateapipb.ResumeActorResponse{
		Actor: &ateapipb.Actor{
			Metadata: &ateapipb.ResourceMetadata{Name: name},
			Status: &ateapipb.ActorStatus{
				State: ateapipb.ActorState_ACTOR_STATE_RUNNING,
				WorkerAssignment: &ateapipb.WorkerAssignment{
					WorkerPod:   "worker-pod-1",
					WorkerPodIp: wIP,
				},
			},
		},
		Resumed: true,
	}, nil
}

func (m *mockControlServer) SuspendActor(ctx context.Context, req *ateapipb.SuspendActorRequest) (*ateapipb.SuspendActorResponse, error) {
	name := ""
	if req.Actor != nil {
		name = req.Actor.Name
	}
	m.suspendedActors = append(m.suspendedActors, name)
	m.events = append(m.events, "suspend")
	if m.suspendError != nil {
		return nil, m.suspendError
	}
	return &ateapipb.SuspendActorResponse{}, nil
}

func (m *mockControlServer) CreateActorEgressPolicy(ctx context.Context, req *ateapipb.CreateActorEgressPolicyRequest) (*ateapipb.EgressPolicy, error) {
	actorName := ""
	if req.Actor != nil {
		actorName = req.Actor.Name
	}
	m.createdPolicies = append(m.createdPolicies, actorName)
	m.policyRequests = append(m.policyRequests, req.EgressPolicy)
	m.events = append(m.events, "policy")
	if m.policyError != nil {
		return nil, m.policyError
	}
	return req.EgressPolicy, nil
}

func (m *mockControlServer) GetActorEgressPolicy(context.Context, *ateapipb.GetActorEgressPolicyRequest) (*ateapipb.EgressPolicy, error) {
	return m.existingPolicy, m.policyReadError
}
func (m *mockControlServer) UpdateActorEgressPolicy(_ context.Context, req *ateapipb.UpdateActorEgressPolicyRequest) (*ateapipb.EgressPolicy, error) {
	m.updatedPolicies = append(m.updatedPolicies, req.EgressPolicy)
	return req.EgressPolicy, nil
}

func (m *mockControlServer) DeleteActor(ctx context.Context, req *ateapipb.DeleteActorRequest) (*ateapipb.Actor, error) {
	name := req.GetActor().GetName()
	m.deletedActors = append(m.deletedActors, name)
	return &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Name: name}}, nil
}

func (m *mockControlServer) ListActorTemplates(ctx context.Context, req *ateapipb.ListActorTemplatesRequest) (*ateapipb.ListActorTemplatesResponse, error) {
	resp := &ateapipb.ListActorTemplatesResponse{}
	for name := range m.actorTemplates {
		resp.ActorTemplates = append(resp.ActorTemplates, &ateapipb.ActorTemplate{
			Metadata: &ateapipb.ResourceMetadata{Name: name, Atespace: req.GetAtespace()},
		})
	}
	return resp, nil
}

func (m *mockControlServer) DeleteActorTemplate(ctx context.Context, req *ateapipb.DeleteActorTemplateRequest) (*ateapipb.ActorTemplate, error) {
	name := req.GetActorTemplate().GetName()
	delete(m.actorTemplates, name)
	m.deletedTemplates = append(m.deletedTemplates, name)
	return &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Name: name}}, nil
}

func securityTestClient(t *testing.T, server *mockControlServer) *substrate.Client {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	ateapipb.RegisterControlServer(grpcServer, server)
	go grpcServer.Serve(lis)
	t.Cleanup(func() { grpcServer.Stop(); lis.Close() })
	client, err := substrate.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestEgressDefaultDenyIsAppliedBeforeResume(t *testing.T) {
	m := &mockControlServer{}
	r := controller.NewTaskReconciler(securityTestClient(t, m), "test-template", "ax-system")
	r.SecretResolver = noSecrets
	// Skip unrelated readiness polling; this test verifies admission ordering.
	task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "deny-default"}, Status: &v1alpha1.TaskStatus{Conditions: []*v1alpha1.Condition{{Type: "WorkspaceReady", Status: "True"}}}}
	if _, err := r.Reconcile(context.Background(), task, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.policyRequests) != 1 || len(m.policyRequests[0].Rules) != 0 {
		t.Fatalf("missing explicit deny-all policy: %v", m.policyRequests)
	}
	if len(m.events) != 2 || m.events[0] != "policy" || m.events[1] != "resume" {
		t.Fatalf("unsafe admission order: %v", m.events)
	}
}

func TestPolicyFailurePreventsResumeAndAttemptsContainment(t *testing.T) {
	for _, suspendFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "suspend succeeds", true: "suspend fails"}[suspendFails], func(t *testing.T) {
			m := &mockControlServer{policyError: status.Error(codes.Unavailable, "control-plane failure")}
			if suspendFails {
				m.suspendError = errors.New("suspension failed")
			}
			r := controller.NewTaskReconciler(securityTestClient(t, m), "test-template", "ax-system")
			r.SecretResolver = noSecrets
			task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "running-task"}, Status: &v1alpha1.TaskStatus{Phase: "Running", WorkerIp: "old-worker"}}
			result, err := r.Reconcile(context.Background(), task, nil)
			if err == nil || result.Status.Phase != "Failed" || result.Status.WorkerIp != "" || len(m.resumedActors) != 0 || len(m.suspendedActors) != 1 {
				t.Fatalf("failed to contain: result=%v err=%v events=%v", result.Status, err, m.events)
			}
			for _, condition := range result.Status.Conditions {
				if condition.Type == "NetworkContainment" && condition.Status == "True" && suspendFails {
					t.Fatal("claimed containment after suspend failed")
				}
			}
		})
	}
}

func TestEarlyAdmissionFailureContainsPreviouslyRunningActor(t *testing.T) {
	for _, stage := range []string{"atespace", "actor", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			m := &mockControlServer{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "atespace":
				m.atespaceError = status.Error(codes.PermissionDenied, "atespace creation unavailable")
			case "actor":
				m.actorError = status.Error(codes.Unavailable, "actor lookup unavailable")
			case "cancelled":
				cancel()
			}
			r := controller.NewTaskReconciler(securityTestClient(t, m), "test-template", "ax-system")
			r.SecretResolver = noSecrets
			task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "existing-actor"}, Status: &v1alpha1.TaskStatus{
				Actor: "untrusted-status-name", Phase: "Running", WorkerIp: "previous-worker"}}
			result, err := r.Reconcile(ctx, task, nil)
			if err == nil || result.Status.Phase != "Failed" || result.Status.WorkerIp != "" || result.Status.Actor != "existing-actor" {
				t.Fatalf("early failure retained running admission: %v, %v", result.Status, err)
			}
			if len(m.resumedActors) != 0 || len(m.policyRequests) != 1 || len(m.policyRequests[0].Rules) != 0 || len(m.suspendedActors) != 1 || m.suspendedActors[0] != "existing-actor" {
				t.Fatalf("early failure skipped containment: events=%v policy=%v actors=%v", m.events, m.policyRequests, m.suspendedActors)
			}
		})
	}
}

func TestEmptyPolicyReplacesExistingBroadPolicy(t *testing.T) {
	m := &mockControlServer{policyError: status.Error(codes.AlreadyExists, "exists"), existingPolicy: &ateapipb.EgressPolicy{Metadata: &ateapipb.ResourceMetadata{Uid: "policy-uid", Version: 7}, Rules: []*ateapipb.EgressRule{{Hostnames: &ateapipb.HostnameRule{Patterns: []string{"*.example.com"}}}}}}
	client := securityTestClient(t, m)
	if err := client.ApplyEgressPolicy(context.Background(), "default", "actor", nil); err != nil {
		t.Fatal(err)
	}
	if len(m.updatedPolicies) != 1 || len(m.updatedPolicies[0].Rules) != 0 || m.updatedPolicies[0].Metadata.Version != 7 {
		t.Fatalf("empty policy did not replace broader policy: %v", m.updatedPolicies)
	}
}

func TestUnsupportedPortAndMalformedPolicyCannotBroadenAccess(t *testing.T) {
	for _, hosts := range [][]*v1alpha1.HostRule{{{Host: "api.example.com", Port: 443}}, {nil}, {{Host: ""}}, {{Host: " example.com"}}} {
		m := &mockControlServer{}
		client := securityTestClient(t, m)
		if err := client.ApplyEgressPolicy(context.Background(), "default", "actor", &v1alpha1.EgressAllowlist{Hosts: hosts}); err == nil {
			t.Fatal("unrepresentable policy accepted")
		}
		if len(m.createdPolicies) != 0 {
			t.Fatal("invalid policy was transmitted")
		}
	}
}

func TestPolicyReadFailureDoesNotBlindlyOverwrite(t *testing.T) {
	m := &mockControlServer{policyError: status.Error(codes.AlreadyExists, "exists"), policyReadError: status.Error(codes.Unavailable, "read failed")}
	client := securityTestClient(t, m)
	if err := client.ApplyEgressPolicy(context.Background(), "default", "actor", nil); err == nil || len(m.updatedPolicies) != 0 {
		t.Fatalf("blind policy update: err=%v updates=%d", err, len(m.updatedPolicies))
	}
}

func TestIPv4AnyCIDRDoesNotAuthorizeIPv6(t *testing.T) {
	m := &mockControlServer{}
	client := securityTestClient(t, m)
	if err := client.ApplyEgressPolicy(context.Background(), "default", "actor", &v1alpha1.EgressAllowlist{Hosts: []*v1alpha1.HostRule{{Host: "0.0.0.0/0"}}}); err != nil {
		t.Fatal(err)
	}
	rules := m.policyRequests[0].Rules
	if len(rules) != 1 || rules[0].All != nil || rules[0].GetCidrs().GetCidrs()[0] != "0.0.0.0/0" {
		t.Fatal("IPv4 scope was broadened to all protocols/address families", rules)
	}
}

func TestInvalidPortPolicyTriggersEmergencyDeny(t *testing.T) {
	m := &mockControlServer{}
	r := controller.NewTaskReconciler(securityTestClient(t, m), "test-template", "ax-system")
	r.SecretResolver = noSecrets
	task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "invalid-policy"}}
	gateway := &v1alpha1.Gateway{Spec: &v1alpha1.GatewaySpec{Egress: &v1alpha1.EgressConfig{Allowlist: &v1alpha1.EgressAllowlist{Hosts: []*v1alpha1.HostRule{{Host: "api.example.com", Port: 443}}}}}}
	_, err := r.Reconcile(context.Background(), task, gateway)
	if err == nil || len(m.resumedActors) != 0 || len(m.policyRequests) != 1 || len(m.policyRequests[0].Rules) != 0 || len(m.suspendedActors) != 1 {
		t.Fatalf("missing emergency deny: err=%v events=%v policies=%v", err, m.events, m.policyRequests)
	}
}

func TestTaskReconciler(t *testing.T) {
	ctx := context.Background()

	// 1. Start in-process mock gRPC Substrate server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	mockSrv := &mockControlServer{}
	grpcServer := grpc.NewServer()
	ateapipb.RegisterControlServer(grpcServer, mockSrv)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	// 2. Initialize Substrate client
	client, err := substrate.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create substrate client: %v", err)
	}
	defer client.Close()

	// 3. Reconcile Task
	reconciler := controller.NewTaskReconciler(client, "test-template", "ax-system")
	reconciler.SecretResolver = noSecrets
	reconciler.WorkspaceReadyTimeout = 200 * time.Millisecond

	task := &v1alpha1.Task{
		ApiVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.KindTask,
		Metadata: &v1alpha1.ObjectMeta{
			Name:     "test-task",
			Atespace: "default",
		},
		Spec: &v1alpha1.TaskSpec{
			Image:   "ghrc.io/my-org/my-image",
			Command: []string{"/bin/task-runner"},
			Gateway: &v1alpha1.GatewayRef{
				Name: "default-gateway",
			},
		},
		// A client-supplied actor name must not survive: the actor is always
		// named after the task.
		Status: &v1alpha1.TaskStatus{Actor: "not-the-task"},
	}

	gateway := &v1alpha1.Gateway{
		Spec: &v1alpha1.GatewaySpec{
			Egress: &v1alpha1.EgressConfig{
				Allowlist: &v1alpha1.EgressAllowlist{
					Hosts: []*v1alpha1.HostRule{
						{Host: "api.anthropic.com"},
						{Host: "github.com"},
					},
				},
			},
		},
	}

	reconciled, err := reconciler.Reconcile(ctx, task, gateway)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 4. Validate reconciliation results
	if reconciled.Status.Phase != "Running" {
		t.Errorf("expected phase 'Running', got %q", reconciled.Status.Phase)
	}
	if reconciled.Status.Actor != "test-task" {
		t.Errorf("expected actor 'test-task', got %q", reconciled.Status.Actor)
	}
	if reconciled.Status.WorkerIp != "10.244.1.42" {
		t.Errorf("expected worker IP '10.244.1.42', got %q", reconciled.Status.WorkerIp)
	}

	// Verify mock was called
	if len(mockSrv.createdAtespaces) != 1 || mockSrv.createdAtespaces[0] != "default" {
		t.Errorf("expected atespace 'default' created, got %v", mockSrv.createdAtespaces)
	}
	if len(mockSrv.createdActors) != 1 || mockSrv.createdActors[0] != "test-task" {
		t.Errorf("expected actor 'test-task' created, got %v", mockSrv.createdActors)
	}
	if len(mockSrv.resumedActors) != 1 || mockSrv.resumedActors[0] != "test-task" {
		t.Errorf("expected actor 'test-task' resumed, got %v", mockSrv.resumedActors)
	}
	if len(mockSrv.createdPolicies) != 1 || mockSrv.createdPolicies[0] != "test-task" {
		t.Errorf("expected egress policy created for 'test-task', got %v", mockSrv.createdPolicies)
	}
}

func TestTaskReconciler_Suspend(t *testing.T) {
	ctx := context.Background()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	mockSrv := &mockControlServer{}
	grpcServer := grpc.NewServer()
	ateapipb.RegisterControlServer(grpcServer, mockSrv)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	client, err := substrate.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create substrate client: %v", err)
	}
	defer client.Close()

	reconciler := controller.NewTaskReconciler(client, "test-template", "ax-system")
	reconciler.SecretResolver = noSecrets
	reconciler.WorkspaceReadyTimeout = 200 * time.Millisecond

	task := &v1alpha1.Task{
		ApiVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.KindTask,
		Metadata: &v1alpha1.ObjectMeta{
			Name:     "suspend-task",
			Atespace: "default",
		},
		Spec: &v1alpha1.TaskSpec{
			Suspend: true,
			Image:   "ghrc.io/my-org/my-image",
		},
	}

	reconciled, err := reconciler.Reconcile(ctx, task, nil)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if reconciled.Status.Phase != "Suspended" {
		t.Errorf("expected phase 'Suspended', got %q", reconciled.Status.Phase)
	}
	if reconciled.Status.WorkerIp != "" {
		t.Errorf("expected empty worker IP, got %q", reconciled.Status.WorkerIp)
	}
	if len(mockSrv.suspendedActors) != 1 || mockSrv.suspendedActors[0] != "suspend-task" {
		t.Errorf("expected actor 'suspend-task' suspended, got %v", mockSrv.suspendedActors)
	}
}

func TestTaskReconciler_WorkspaceReady(t *testing.T) {
	ctx := context.Background()

	// 1. Mock Substrate Control Server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	// 2. Mock Worker readyz HTTP server
	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen http: %v", err)
	}
	defer httpLis.Close()

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	httpServer := &http.Server{Handler: httpMux}
	go httpServer.Serve(httpLis)
	defer httpServer.Close()

	workerHost, workerPortStr, _ := net.SplitHostPort(httpLis.Addr().String())
	// In our mock, the worker IP returned by ResumeActor will have our mock ready server listening.
	// But our reconciler connects to port 9999 by default: fmt.Sprintf("http://%s:9999/readyz", workerIP).
	// If workerIP includes a port or is a host, let's verify how it handles it.
	_ = workerHost
	_ = workerPortStr

	mockSrv := &mockControlServer{}
	grpcServer := grpc.NewServer()
	ateapipb.RegisterControlServer(grpcServer, mockSrv)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	client, err := substrate.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create substrate client: %v", err)
	}
	defer client.Close()

	reconciler := controller.NewTaskReconciler(client, "test-template", "ax-system")
	reconciler.SecretResolver = noSecrets
	reconciler.WorkspaceReadyTimeout = 200 * time.Millisecond

	task := &v1alpha1.Task{
		ApiVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.KindTask,
		Metadata: &v1alpha1.ObjectMeta{
			Name:     "ready-task",
			Atespace: "default",
		},
		Spec: &v1alpha1.TaskSpec{},
	}

	// Case 1: Worker not responding on readyz -> WorkspaceReady=False and Ready=False.
	reconciled, err := reconciler.Reconcile(ctx, task, nil)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	assertCondition(t, reconciled, "WorkspaceReady", "False", "Initializing")
	assertCondition(t, reconciled, "Ready", "False", "WorkspaceInitializing")

	// Case 2: Worker readyz endpoint succeeds -> WorkspaceReady=True and Ready=True.
	mockSrv.workerIP = httpLis.Addr().String()
	reconciledReady, err := reconciler.Reconcile(ctx, task, nil)
	if err != nil {
		t.Fatalf("Reconcile with ready worker failed: %v", err)
	}
	assertCondition(t, reconciledReady, "WorkspaceReady", "True", "SetupComplete")
	assertCondition(t, reconciledReady, "Ready", "True", "TaskRunning")

	// Case 3: Suspending the task -> Ready=False (TaskSuspended), but the workspace was
	// already initialized so WorkspaceReady stays True.
	task = reconciledReady
	task.Spec.Suspend = true
	reconciledSuspended, err := reconciler.Reconcile(ctx, task, nil)
	if err != nil {
		t.Fatalf("Reconcile with suspend failed: %v", err)
	}
	if reconciledSuspended.Status.Phase != "Suspended" {
		t.Errorf("expected phase Suspended, got %s", reconciledSuspended.Status.Phase)
	}
	assertCondition(t, reconciledSuspended, "Ready", "False", "TaskSuspended")
	assertCondition(t, reconciledSuspended, "WorkspaceReady", "True", "SetupComplete")

	// Case 4: Resuming with the worker unreachable -> the reconciler trusts the recorded
	// WorkspaceReady instead of re-polling, so the task is Ready again immediately.
	mockSrv.workerIP = "127.0.0.1:1"
	task = reconciledSuspended
	task.Spec.Suspend = false
	reconciledResumed, err := reconciler.Reconcile(ctx, task, nil)
	if err != nil {
		t.Fatalf("Reconcile with resume failed: %v", err)
	}
	assertCondition(t, reconciledResumed, "WorkspaceReady", "True", "SetupComplete")
	assertCondition(t, reconciledResumed, "Ready", "True", "TaskRunning")
}

// assertCondition fails the test unless the task has a condition of the given type with
// the expected status and reason.
func assertCondition(t *testing.T, task *v1alpha1.Task, condType, wantStatus, wantReason string) {
	t.Helper()
	for _, c := range task.Status.Conditions {
		if c.Type != condType {
			continue
		}
		if c.Status != wantStatus || c.Reason != wantReason {
			t.Errorf("expected %s=%s (%s), got Status=%s Reason=%s", condType, wantStatus, wantReason, c.Status, c.Reason)
		}
		return
	}
	t.Errorf("expected %s condition to be set", condType)
}

func TestReconcileDelete_RemovesActorAndTemplates(t *testing.T) {
	ctx := context.Background()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	mockSrv := &mockControlServer{actorTemplates: map[string]bool{
		"job-tmpl-0a1b2c3d":               true, // current revision of task "job"
		"job-tmpl-deadbeef":               true, // stale revision of task "job"
		"job-tmpl-deadbeef-tmpl-01234567": true, // belongs to a task literally named "job-tmpl-deadbeef"
		"jobs-tmpl-0a1b2c3d":              true, // belongs to task "jobs"
		"default-template":                true,
	}}
	grpcServer := grpc.NewServer()
	ateapipb.RegisterControlServer(grpcServer, mockSrv)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	client, err := substrate.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create substrate client: %v", err)
	}
	defer client.Close()

	reconciler := controller.NewTaskReconciler(client, "test-template", "ax-system")
	reconciler.SecretResolver = noSecrets
	reconciler.WorkspaceReadyTimeout = 200 * time.Millisecond

	if err := reconciler.ReconcileDelete(ctx, "default", "job"); err != nil {
		t.Fatalf("ReconcileDelete failed: %v", err)
	}

	if len(mockSrv.deletedActors) != 1 || mockSrv.deletedActors[0] != "job" {
		t.Errorf("expected actor 'job' to be deleted, got %v", mockSrv.deletedActors)
	}

	wantDeleted := map[string]bool{"job-tmpl-0a1b2c3d": true, "job-tmpl-deadbeef": true}
	if len(mockSrv.deletedTemplates) != len(wantDeleted) {
		t.Errorf("expected %d templates deleted, got %v", len(wantDeleted), mockSrv.deletedTemplates)
	}
	for _, name := range mockSrv.deletedTemplates {
		if !wantDeleted[name] {
			t.Errorf("unexpected template deleted: %s", name)
		}
	}
	for _, keep := range []string{"job-tmpl-deadbeef-tmpl-01234567", "jobs-tmpl-0a1b2c3d", "default-template"} {
		if !mockSrv.actorTemplates[keep] {
			t.Errorf("template %s should not have been deleted", keep)
		}
	}
}
