package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/ax/internal/store"
	"github.com/google/ax/pkg/apis/v1alpha1"
	redisclient "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

// These integration tests use a private, ephemeral Unix socket and disable TCP,
// persistence and append-only logs. They never contact an existing Redis server.
func isolatedTaskRedis(t *testing.T) (*Store, *Store) {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server is required for transaction integration tests")
	}
	directory, err := os.MkdirTemp("", "ax-redis-")
	if err != nil {
		t.Fatal(err)
	}
	// macOS Unix-domain paths are short; use /tmp if the test runner's temporary
	// root would exceed sockaddr_un's portable path size.
	if len(directory) > 75 {
		os.Remove(directory)
		directory, err = os.MkdirTemp("/tmp", "ax-redis-")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "redis.sock")
	command := exec.Command(binary, "--port", "0", "--unixsocket", socket,
		"--unixsocketperm", "700", "--save", "", "--appendonly", "no",
		"--dir", directory, "--logfile", filepath.Join(directory, "redis.log"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.Process.Kill(); command.Wait() })
	newClient := func() *redisclient.Client {
		client := redisclient.NewClient(&redisclient.Options{Network: "unix", Addr: socket,
			Protocol: 2, DisableIdentity: true, DialTimeout: 100 * time.Millisecond,
			ReadTimeout: time.Second, WriteTimeout: time.Second})
		t.Cleanup(func() { client.Close() })
		return client
	}
	client := newClient()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for client.Ping(ctx).Err() != nil {
		if ctx.Err() != nil {
			log, _ := os.ReadFile(filepath.Join(directory, "redis.log"))
			t.Fatalf("private Redis did not start: %v\n%s", ctx.Err(), log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return NewStore(client, Options{TTL: time.Minute}), NewStore(newClient(), Options{TTL: time.Minute})
}

type taskInterleaveHook struct {
	afterRead      func(int) error
	reads, watches int
}

func (h *taskInterleaveHook) DialHook(next redisclient.DialHook) redisclient.DialHook { return next }
func (h *taskInterleaveHook) ProcessPipelineHook(next redisclient.ProcessPipelineHook) redisclient.ProcessPipelineHook {
	return next
}
func (h *taskInterleaveHook) ProcessHook(next redisclient.ProcessHook) redisclient.ProcessHook {
	return func(ctx context.Context, cmd redisclient.Cmder) error {
		if err := next(ctx, cmd); err != nil {
			return err
		}
		if cmd.Name() == "watch" {
			h.watches++
		}
		if cmd.Name() == "get" && h.afterRead != nil {
			h.reads++
			return h.afterRead(h.reads)
		}
		return nil
	}
}

func saveMutationTask(t *testing.T, s *Store) *v1alpha1.Task {
	t.Helper()
	task := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Image: "old"}}
	if err := s.SaveTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	return task
}

func TestStatusTransactionRetainsConcurrentDesiredSpec(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	task := saveMutationTask(t, s)
	hook := &taskInterleaveHook{afterRead: func(read int) error {
		if read != 1 {
			return nil
		}
		task.Spec.Image = "new-concurrent-image"
		return other.SaveTask(context.Background(), task)
	}}
	s.client.AddHook(hook)
	if err := s.UpdateTaskStatus(context.Background(), "", "task", &v1alpha1.TaskStatus{Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	stored, err := other.GetTask(context.Background(), "default", "task")
	if err != nil || stored.Spec.Image != "new-concurrent-image" || stored.Status.Phase != "Running" || hook.watches != 2 {
		t.Fatalf("status overwrote concurrent desired spec or skipped CAS retry: %v err=%v watches=%d", stored, err, hook.watches)
	}
	if exists := other.client.Exists(context.Background(), s.taskKey("", "task")).Val(); exists != 0 {
		t.Fatal("default-atespace status wrote a separate unscoped task key")
	}
}

func TestStatusTransactionCannotClearConcurrentDeleteMark(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	saveMutationTask(t, s)
	s.client.AddHook(&taskInterleaveHook{afterRead: func(read int) error {
		if read == 1 {
			return other.MarkTaskDeleting(context.Background(), "default", "task")
		}
		return nil
	}})
	if err := s.UpdateTaskStatus(context.Background(), "default", "task", &v1alpha1.TaskStatus{Phase: "Running", WorkerIp: "stale"}); err != nil {
		t.Fatal(err)
	}
	stored, err := other.GetTask(context.Background(), "default", "task")
	if err != nil || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating || stored.GetStatus().GetWorkerIp() == "stale" {
		t.Fatalf("late status erased deletion: %v err=%v", stored, err)
	}
	if err := s.UpdateTaskStatus(context.Background(), "default", "task", nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = other.GetTask(context.Background(), "default", "task")
	if stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating {
		t.Fatal("nil status erased deletion")
	}
}

func TestDeleteMarkTransactionRetainsConcurrentDesiredSpec(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	task := saveMutationTask(t, s)
	s.client.AddHook(&taskInterleaveHook{afterRead: func(read int) error {
		if read != 1 {
			return nil
		}
		task.Spec.Image = "changed-before-delete"
		return other.SaveTask(context.Background(), task)
	}})
	if err := s.MarkTaskDeleting(context.Background(), "default", "task"); err != nil {
		t.Fatal(err)
	}
	stored, err := other.GetTask(context.Background(), "default", "task")
	if err != nil || stored.Spec.Image != "changed-before-delete" || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating {
		t.Fatalf("delete mark overwrote concurrent desired spec: %v err=%v", stored, err)
	}
	events, err := other.client.XRange(context.Background(), other.opts.StreamName, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	deletes := 0
	for _, event := range events {
		if event.Values["action"] == "delete" {
			deletes++
		}
	}
	if deletes != 1 {
		t.Fatalf("aborted transaction published an event: %d delete events", deletes)
	}
}

func TestStatusTransactionCannotResurrectDeletedTask(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	saveMutationTask(t, s)
	s.client.AddHook(&taskInterleaveHook{afterRead: func(read int) error {
		if read == 1 {
			return other.DeleteTask(context.Background(), "default", "task")
		}
		return nil
	}})
	if err := s.UpdateTaskStatus(context.Background(), "default", "task", &v1alpha1.TaskStatus{Phase: "Running"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing task error was hidden: %v", err)
	}
	if _, err := other.GetTask(context.Background(), "default", "task"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("status recreated deleted task: %v", err)
	}
}

func TestTaskMutationConflictsAreBoundedAndVisible(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	task := saveMutationTask(t, s)
	hook := &taskInterleaveHook{afterRead: func(read int) error {
		task.Spec.Image = fmt.Sprintf("concurrent-%d", read)
		return other.SaveTask(context.Background(), task)
	}}
	s.client.AddHook(hook)
	err := s.UpdateTaskStatus(context.Background(), "default", "task", &v1alpha1.TaskStatus{Phase: "Running"})
	if !errors.Is(err, redisclient.TxFailedErr) || hook.watches != taskMutationAttempts {
		t.Fatalf("conflicts were hidden or retried without bound: %v watches=%d", err, hook.watches)
	}
}

func TestTaskMutationPreservesConfiguredTTLAndListingOrder(t *testing.T) {
	s, _ := isolatedTaskRedis(t)
	saveMutationTask(t, s)
	ctx := context.Background()
	key := s.taskKey("default", "task")
	before := s.client.ZScore(ctx, s.taskIndexKey(), "default:task").Val()
	if err := s.client.PExpire(ctx, key, 3*time.Second).Err(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTaskStatus(ctx, "default", "task", &v1alpha1.TaskStatus{Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	if ttl := s.client.PTTL(ctx, key).Val(); ttl < 50*time.Second || ttl > time.Minute {
		t.Fatalf("configured TTL refresh changed: %s", ttl)
	}
	if err := s.MarkTaskDeleting(ctx, "default", "task"); err != nil {
		t.Fatal(err)
	}
	if score := s.client.ZScore(ctx, s.taskIndexKey(), "default:task").Val(); score != before {
		t.Fatal("status/delete mark reordered task index")
	}
}

func TestSaveTaskRejectsPersistedTermination(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	ctx := context.Background()
	saveMutationTask(t, s)
	if err := s.MarkTaskDeleting(ctx, "default", "task"); err != nil {
		t.Fatal(err)
	}
	before, err := other.GetTask(ctx, "default", "task")
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := other.client.XLen(ctx, other.opts.StreamName).Val()
	for _, phase := range []string{"", "Pending", "Running", "Suspended", v1alpha1.PhaseTerminating} {
		t.Run("incoming-"+phase, func(t *testing.T) {
			stale := &v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: "task"}, Spec: &v1alpha1.TaskSpec{Image: "overwrite"}}
			if phase != "" {
				stale.Status = &v1alpha1.TaskStatus{Phase: phase}
			}
			if err := s.SaveTask(ctx, stale); !errors.Is(err, store.ErrTaskTerminating) {
				t.Fatalf("save accepted existing delete mark: %v", err)
			}
			after, err := other.GetTask(ctx, "default", "task")
			if err != nil || !proto.Equal(before, after) {
				t.Fatalf("rejected save modified record: %v, %v", after, err)
			}
		})
	}
	if count := other.client.XLen(ctx, other.opts.StreamName).Val(); count != eventsBefore {
		t.Fatal("rejected saves published task events")
	}
}

func TestSaveTaskCannotRacePastConcurrentDeleteMark(t *testing.T) {
	for _, suspend := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale-suspend-%v", suspend), func(t *testing.T) {
			s, other := isolatedTaskRedis(t)
			ctx := context.Background()
			stale := saveMutationTask(t, s)
			stale.Spec.Suspend = suspend
			stale.Spec.Image = "stale-override"
			stale.Status = &v1alpha1.TaskStatus{Phase: "Running"}
			hook := &taskInterleaveHook{afterRead: func(read int) error {
				if read == 1 {
					return other.MarkTaskDeleting(ctx, "default", "task")
				}
				return nil
			}}
			s.client.AddHook(hook)
			if err := s.SaveTask(ctx, stale); !errors.Is(err, store.ErrTaskTerminating) {
				t.Fatalf("concurrent delete was overwritten: %v", err)
			}
			stored, err := other.GetTask(ctx, "default", "task")
			if err != nil || stored.Spec.Image != "old" || stored.GetStatus().GetPhase() != v1alpha1.PhaseTerminating || hook.watches != 2 {
				t.Fatalf("stale save escaped watched delete: %v err=%v watches=%d", stored, err, hook.watches)
			}
			events, err := other.client.XRange(ctx, other.opts.StreamName, "-", "+").Result()
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 2 || events[0].Values["action"] != "reconcile" || events[1].Values["action"] != "delete" {
				t.Fatalf("aborted save published an event: %v", events)
			}
		})
	}
}

func TestSaveTaskConflictsAreBoundedAndVisible(t *testing.T) {
	s, other := isolatedTaskRedis(t)
	ctx := context.Background()
	stale := saveMutationTask(t, s)
	hook := &taskInterleaveHook{afterRead: func(int) error {
		return other.UpdateTaskStatus(ctx, "default", "task", &v1alpha1.TaskStatus{Phase: "Pending"})
	}}
	s.client.AddHook(hook)
	err := s.SaveTask(ctx, stale)
	if !errors.Is(err, redisclient.TxFailedErr) || hook.watches != taskMutationAttempts {
		t.Fatalf("save conflict retries unbounded or hidden: %v watches=%d", err, hook.watches)
	}
}
