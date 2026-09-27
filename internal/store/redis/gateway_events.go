package redis

import (
	"context"
	"fmt"

	"github.com/google/ax/pkg/apis/v1alpha1"
	"github.com/redis/go-redis/v9"
)

func (s *Store) EnqueueGatewayTasks(ctx context.Context, atespace, name string) error {
	if atespace == "" {
		atespace = "default"
	}
	if name == "" {
		return fmt.Errorf("gateway name is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Snapshot the complete exact-atespace index. Offset paging a changing
	// newest-first index can miss tasks; ListTasks also has a default limit and
	// suppresses malformed records, neither of which is safe for this fanout.
	names, err := s.client.ZRange(ctx, s.taskAtespaceIndexKey(atespace), 0, -1).Result()
	if err != nil {
		return fmt.Errorf("listing gateway task bindings: %w", err)
	}
	const batchSize = 256
	for start := 0; start < len(names); start += batchSize {
		end := min(start+batchSize, len(names))
		keys := make([]string, end-start)
		for i, taskName := range names[start:end] {
			keys[i] = s.taskKey(atespace, taskName)
		}
		values, err := s.client.MGet(ctx, keys...).Result()
		if err != nil {
			return fmt.Errorf("reading gateway task bindings (publication may be partial): %w", err)
		}
		if len(values) != len(keys) {
			return fmt.Errorf("incomplete gateway task binding read (publication may be partial)")
		}
		pipe := s.client.Pipeline()
		for i, value := range values {
			if value == nil {
				continue // Task was deleted or expired after the index snapshot.
			}
			data, ok := value.(string)
			if !ok {
				return fmt.Errorf("invalid task record %q (publication may be partial)", names[start+i])
			}
			var task v1alpha1.Task
			if err := jsonUnmarshalOpts.Unmarshal([]byte(data), &task); err != nil {
				return fmt.Errorf("decoding task %q (publication may be partial): %w", names[start+i], err)
			}
			taskAtespace := task.GetMetadata().GetAtespace()
			if taskAtespace == "" {
				taskAtespace = "default"
			}
			if taskAtespace != atespace || task.GetMetadata().GetName() != names[start+i] {
				return fmt.Errorf("task identity disagrees with scoped index (publication may be partial)")
			}
			if task.GetSpec().GetGateway().GetName() != name || task.GetStatus().GetPhase() == v1alpha1.PhaseTerminating {
				continue
			}
			pipe.XAdd(ctx, &redis.XAddArgs{
				Stream: s.opts.StreamName,
				Values: map[string]interface{}{"action": "reconcile", "atespace": atespace, "name": names[start+i]},
			})
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("publishing gateway task events (publication may be partial): %w", err)
		}
	}
	return nil
}
