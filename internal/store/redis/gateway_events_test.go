package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/ax/pkg/apis/v1alpha1"
	redisclient "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/encoding/protojson"
)

// Intercept commands at the client boundary: tests never connect to Redis or
// another service, and unexpected commands fail instead of reaching a socket.
type gatewayRedisHook struct {
	t           *testing.T
	names       []string
	records     map[string]interface{}
	events      []map[string]string
	readErr     error
	writeErr    error
	readBatches int
}

func (h *gatewayRedisHook) DialHook(redisclient.DialHook) redisclient.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected network call")
	}
}

func (h *gatewayRedisHook) ProcessHook(redisclient.ProcessHook) redisclient.ProcessHook {
	return func(_ context.Context, cmd redisclient.Cmder) error {
		args := cmd.Args()
		switch cmd.Name() {
		case "zrange":
			if len(args) != 4 || args[1] != "ax:tasks:atespace:tenant-a" || fmt.Sprint(args[2]) != "0" || fmt.Sprint(args[3]) != "-1" {
				h.t.Fatalf("index query was capped or unscoped: %v", args)
			}
			cmd.(*redisclient.StringSliceCmd).SetVal(h.names)
		case "mget":
			h.readBatches++
			if h.readErr != nil {
				return h.readErr
			}
			if len(args) > 257 {
				h.t.Fatalf("unbounded fetch batch: %d", len(args)-1)
			}
			values := make([]interface{}, len(args)-1)
			for i, key := range args[1:] {
				values[i] = h.records[key.(string)]
			}
			cmd.(*redisclient.SliceCmd).SetVal(values)
		default:
			h.t.Fatalf("unexpected Redis command: %v", args)
		}
		return nil
	}
}

func (h *gatewayRedisHook) ProcessPipelineHook(redisclient.ProcessPipelineHook) redisclient.ProcessPipelineHook {
	return func(_ context.Context, cmds []redisclient.Cmder) error {
		if h.writeErr != nil {
			return h.writeErr
		}
		for _, cmd := range cmds {
			args := cmd.Args()
			if cmd.Name() != "xadd" || args[1] != "ax:stream:tasks" || args[2] != "*" {
				h.t.Fatalf("fanout changed records or queue options: %v", args)
			}
			event := make(map[string]string)
			for i := 3; i < len(args); i += 2 {
				event[args[i].(string)] = args[i+1].(string)
			}
			h.events = append(h.events, event)
			cmd.(*redisclient.StringCmd).SetVal(fmt.Sprintf("%d-0", len(h.events)))
		}
		return nil
	}
}

func gatewayRedisFixture(t *testing.T, count int) (*Store, *gatewayRedisHook) {
	t.Helper()
	h := &gatewayRedisHook{t: t, records: make(map[string]interface{})}
	for i := range count {
		name := fmt.Sprintf("task-%d", i)
		h.names = append(h.names, name)
		data, err := protojson.Marshal(&v1alpha1.Task{Metadata: &v1alpha1.ObjectMeta{Name: name, Atespace: "tenant-a"}, Spec: &v1alpha1.TaskSpec{Gateway: &v1alpha1.GatewayRef{Name: "gateway"}}})
		if err != nil {
			t.Fatal(err)
		}
		h.records["ax:task:tenant-a:"+name] = string(data)
	}
	client := redisclient.NewClient(&redisclient.Options{Addr: "unused.invalid:1"})
	client.AddHook(h)
	t.Cleanup(func() { client.Close() })
	return NewStore(client, Options{}), h
}

func TestRedisGatewayFanoutHasNoTaskLimit(t *testing.T) {
	s, h := gatewayRedisFixture(t, 1237)
	// Missing/expired, unrelated and terminating records do not generate work.
	delete(h.records, "ax:task:tenant-a:task-0")
	h.records["ax:task:tenant-a:task-1"] = `{"metadata":{"name":"task-1","atespace":"tenant-a"},"spec":{"gateway":{"name":"different"}}}`
	h.records["ax:task:tenant-a:task-2"] = `{"metadata":{"name":"task-2","atespace":"tenant-a"},"spec":{"gateway":{"name":"gateway"}},"status":{"phase":"Terminating"}}`
	if err := s.EnqueueGatewayTasks(context.Background(), "tenant-a", "gateway"); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1234 || h.readBatches != 5 {
		t.Fatalf("incomplete fanout: %d events, %d batches", len(h.events), h.readBatches)
	}
	seen := make(map[string]bool)
	for _, ev := range h.events {
		if ev["atespace"] != "tenant-a" || ev["action"] != "reconcile" || seen[ev["name"]] {
			t.Fatalf("invalid event: %v", ev)
		}
		seen[ev["name"]] = true
	}
	for i := 3; i < 1237; i++ {
		if !seen[fmt.Sprintf("task-%d", i)] {
			t.Fatalf("binding %d missed", i)
		}
	}
}

func TestRedisGatewayFanoutErrorsCannotBeSilentlySkipped(t *testing.T) {
	for _, reason := range []string{"read", "publication", "malformed", "cross-namespace", "wrong-name"} {
		t.Run(reason, func(t *testing.T) {
			s, h := gatewayRedisFixture(t, 1)
			switch reason {
			case "read":
				h.readErr = errors.New("read unavailable")
			case "publication":
				h.writeErr = errors.New("queue unavailable")
			case "malformed":
				h.records["ax:task:tenant-a:task-0"] = "{invalid"
			case "cross-namespace":
				h.records["ax:task:tenant-a:task-0"] = `{"metadata":{"name":"task-0","atespace":"tenant-b"},"spec":{"gateway":{"name":"gateway"}}}`
			case "wrong-name":
				h.records["ax:task:tenant-a:task-0"] = `{"metadata":{"name":"other","atespace":"tenant-a"},"spec":{"gateway":{"name":"gateway"}}}`
			}
			if err := s.EnqueueGatewayTasks(context.Background(), "tenant-a", "gateway"); err == nil || !strings.Contains(err.Error(), "partial") {
				t.Fatalf("failed publication was hidden: %v", err)
			}
			if len(h.events) != 0 {
				t.Fatalf("invalid binding generated events: %v", h.events)
			}
		})
	}
}
