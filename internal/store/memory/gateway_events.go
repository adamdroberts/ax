package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/google/ax/internal/store"
	"github.com/google/ax/pkg/apis/v1alpha1"
)

func (s *MemoryStore) EnqueueGatewayTasks(ctx context.Context, atespace, name string) error {
	if atespace == "" {
		atespace = "default"
	}
	if name == "" {
		return fmt.Errorf("gateway name is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The snapshot has no pagination or count ceiling. Release the store lock
	// before publishing so a full queue never blocks its consumer's store reads.
	s.mu.RLock()
	var names []string
	for _, task := range s.tasks {
		if task.GetMetadata().GetAtespace() == atespace &&
			task.GetSpec().GetGateway().GetName() == name &&
			task.GetStatus().GetPhase() != v1alpha1.PhaseTerminating {
			names = append(names, task.GetMetadata().GetName())
		}
	}
	s.mu.RUnlock()

	// Unlike the best-effort watcher notifications, security reconciliation
	// events must never be silently dropped. Bound backpressure even if the
	// caller supplied no deadline and no controller is consuming the queue.
	publishCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for i, taskName := range names {
		if err := publishCtx.Err(); err != nil {
			return fmt.Errorf("gateway reconciliation published %d of %d events: %w", i, len(names), err)
		}
		event := store.TaskEvent{
			ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
			Atespace: atespace, Name: taskName, Action: "reconcile",
		}
		select {
		case s.events <- event:
		case <-publishCtx.Done():
			return fmt.Errorf("gateway reconciliation published %d of %d events: %w", i, len(names), publishCtx.Err())
		}
	}
	return nil
}
