package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/ax/internal/store"
	"github.com/google/ax/pkg/apis/v1alpha1"
	"github.com/redis/go-redis/v9"
)

const taskMutationAttempts = 5

// SaveTask remains an upsert when the key is absent. The watched read prevents
// a stale whole-record save from clearing a delete mark that still exists; it
// does not provide incarnation fencing after physical deletion/name reuse.
func (s *Store) saveTaskUnlessTerminating(ctx context.Context, atespace, name string, data []byte) error {
	key := s.taskKey(atespace, name)
	for attempt := 0; attempt < taskMutationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.client.Watch(ctx, func(tx *redis.Tx) error {
			current, err := tx.Get(ctx, key).Bytes()
			if err != nil && !errors.Is(err, redis.Nil) {
				return fmt.Errorf("reading existing task: %w", err)
			}
			if err == nil {
				var existing v1alpha1.Task
				if err := jsonUnmarshalOpts.Unmarshal(current, &existing); err != nil {
					return fmt.Errorf("decoding existing task: %w", err)
				}
				if existing.GetStatus().GetPhase() == v1alpha1.PhaseTerminating {
					return store.ErrTaskTerminating
				}
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				score := float64(time.Now().UnixNano())
				pipe.Set(ctx, key, data, s.opts.TTL)
				pipe.ZAdd(ctx, s.taskIndexKey(), redis.Z{Score: score, Member: atespace + ":" + name})
				pipe.ZAdd(ctx, s.taskAtespaceIndexKey(atespace), redis.Z{Score: score, Member: name})
				pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.opts.StreamName,
					Values: map[string]interface{}{"action": "reconcile", "atespace": atespace, "name": name}})
				pipe.Publish(ctx, s.taskPubSubChannel(atespace, name), data)
				return nil
			})
			return err
		}, key)
		if !errors.Is(err, redis.TxFailedErr) {
			if err != nil {
				return fmt.Errorf("saving task %s/%s atomically: %w", atespace, name, err)
			}
			return nil
		}
	}
	return fmt.Errorf("task %s/%s changed during all %d save attempts: %w", atespace, name, taskMutationAttempts, redis.TxFailedErr)
}

// mutateTask protects the read/merge/write against every concurrent key update,
// including SaveTask, deletion, and another controller process. Each retry
// merges into the latest record; no stale desired spec is ever written back.
func (s *Store) mutateTask(ctx context.Context, atespace, name, action string, mutate func(*v1alpha1.Task) bool) error {
	if atespace == "" {
		atespace = "default"
	}
	key := s.taskKey(atespace, name)
	for attempt := 0; attempt < taskMutationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.client.Watch(ctx, func(tx *redis.Tx) error {
			data, err := tx.Get(ctx, key).Bytes()
			if errors.Is(err, redis.Nil) {
				return store.ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("reading task: %w", err)
			}
			var task v1alpha1.Task
			if err := jsonUnmarshalOpts.Unmarshal(data, &task); err != nil {
				return fmt.Errorf("decoding task: %w", err)
			}
			if !mutate(&task) {
				return nil
			}
			updated, err := jsonMarshalOpts.Marshal(&task)
			if err != nil {
				return fmt.Errorf("encoding task: %w", err)
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				// Retain the existing configured-TTL refresh behavior. Status and
				// delete-mark mutations do not alter either task listing index.
				pipe.Set(ctx, key, updated, s.opts.TTL)
				pipe.Publish(ctx, s.taskPubSubChannel(atespace, name), updated)
				if action != "" {
					pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.opts.StreamName,
						Values: map[string]interface{}{"action": action, "atespace": atespace, "name": name}})
				}
				return nil
			})
			return err
		}, key)
		if !errors.Is(err, redis.TxFailedErr) {
			if err != nil {
				return fmt.Errorf("updating task %s/%s atomically: %w", atespace, name, err)
			}
			return nil
		}
	}
	return fmt.Errorf("task %s/%s changed during all %d update attempts: %w", atespace, name, taskMutationAttempts, redis.TxFailedErr)
}
