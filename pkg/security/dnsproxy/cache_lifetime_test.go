package dnsproxy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type lifetimeResolverFunc func(context.Context, string) (Resolution, error)

func (f lifetimeResolverFunc) Resolve(ctx context.Context, name string) (Resolution, error) {
	return f(ctx, name)
}

// Check both reconstructed address families over both reply framing modes.
// These calls must remain cache-only, including denial and expiry.
func checkLifetimeAnswer(t *testing.T, p *Proxy, admitted bool) {
	t.Helper()
	before := p.Stats().UpstreamLookups
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		for _, tcp := range []bool{false, true} {
			m := unpack(t, p.Answer(query(t, "api.example.test.", kind), tcp))
			if admitted {
				if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
					t.Fatalf("type %d tcp=%v: timely cache answer was lost: %+v", kind, tcp, m)
				}
			} else if m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
				t.Fatalf("type %d tcp=%v: expired or canceled refresh returned addresses: %+v", kind, tcp, m)
			}
		}
	}
	if p.Stats().UpstreamLookups != before {
		t.Fatal("client answer scheduled an upstream lookup")
	}
}

func TestRefreshLifetimeBounds(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		ttl, delay, interval, lifetime time.Duration
	}{
		{"upstream-ttl", 15 * time.Second, 2 * time.Second, 10 * time.Second, 15 * time.Second},
		{"refresh-cap-min", time.Hour, 2 * time.Second, 10 * time.Second, 20 * time.Second},
		{"refresh-cap-default", time.Hour, 2 * time.Second, time.Minute, 2 * time.Minute},
		{"refresh-cap-max", time.Hour, 2 * time.Second, 5 * time.Minute, 10 * time.Minute},
		{"equal-ttl-and-cap", 20 * time.Second, 2 * time.Second, 10 * time.Second, 20 * time.Second},
		{"one-ns-remaining", 2*time.Second + time.Nanosecond, 2 * time.Second, 10 * time.Second, 2*time.Second + time.Nanosecond},
		{"expired-at-return", 2 * time.Second, 2 * time.Second, 10 * time.Second, 0},
		{"expired-before-return", time.Second, 2 * time.Second, 10 * time.Second, 0},
		{"zero-ttl", 0, 0, 10 * time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				resolver := lifetimeResolverFunc(func(context.Context, string) (Resolution, error) {
					calls++
					time.Sleep(tc.delay)
					result := fakePublic().result
					result.TTL = tc.ttl
					return result, nil
				})
				p, err := New(Config{AllowedNames: []string{"api.example.test"}, RefreshInterval: tc.interval}, resolver)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				p.Refresh(context.Background())
				checkLifetimeAnswer(t, p, tc.lifetime != 0)
				if tc.lifetime != 0 {
					deadline := start.Add(tc.lifetime)
					if got := p.cache["api.example.test."].expires; !got.Equal(deadline) {
						t.Fatalf("cache expiry extended by lookup time: got %v, want %v", got.Sub(start), tc.lifetime)
					}
					time.Sleep(time.Until(deadline) - time.Nanosecond)
					checkLifetimeAnswer(t, p, true)
					m := unpack(t, p.Answer(query(t, "api.example.test.", dnsmessage.TypeA), false))
					if m.Answers[0].Header.TTL != 0 {
						t.Fatal("subsecond lifetime was rounded upward")
					}
					time.Sleep(time.Nanosecond)
					checkLifetimeAnswer(t, p, false)
					time.Sleep(time.Second)
					checkLifetimeAnswer(t, p, false)
				}
				if calls != 1 || p.Stats().UpstreamLookups != 1 {
					t.Fatal("cache queries caused an extra lookup")
				}
			})
		})
	}
}

func TestRefreshDiscardsCanceledResults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		admitted bool
	}{
		{"immediate-success", true},
		{"before-timeout", true},
		{"at-timeout", false},
		{"after-timeout", false},
		{"after-context-signal", false},
		{"parent-cancel", false},
		{"parent-deadline", false},
		{"resolver-error", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, original := testProxy(t)
				p.timeout = time.Second
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				if tc.name == "parent-deadline" {
					var stop context.CancelFunc
					parent, stop = context.WithTimeout(parent, 500*time.Millisecond)
					defer stop()
				}
				calls := 0
				p.resolver = lifetimeResolverFunc(func(ctx context.Context, _ string) (Resolution, error) {
					calls++
					result := fakePublic().result
					result.Addresses[0] = netip.MustParseAddr("8.8.4.4")
					switch tc.name {
					case "before-timeout":
						time.Sleep(time.Second - time.Nanosecond)
					case "at-timeout":
						time.Sleep(time.Second)
					case "after-timeout":
						time.Sleep(time.Second + time.Nanosecond)
					case "after-context-signal", "parent-deadline":
						<-ctx.Done()
					case "parent-cancel":
						cancel()
					case "resolver-error":
						return result, errors.New("refresh failed with partial addresses")
					}
					// Deliberately return addresses with nil error even after the
					// context ends, reproducing cancellation/completion races.
					return result, nil
				})
				p.Refresh(parent)
				checkLifetimeAnswer(t, p, tc.admitted)
				wantFailures := uint64(1)
				if tc.admitted {
					wantFailures = 0
					m := unpack(t, p.Answer(query(t, "api.example.test.", dnsmessage.TypeA), false))
					if got := m.Answers[0].Body.(*dnsmessage.AResource).A; got != [4]byte{8, 8, 4, 4} {
						t.Fatal("successful refresh retained the previous address", got)
					}
				}
				if calls != 1 || original.count() != 1 || p.Stats().UpstreamLookups != 2 || p.Stats().RefreshFailures != wantFailures {
					t.Fatal("refresh accounting or cache-only query behavior changed", p.Stats())
				}
				// A subsequent independent valid refresh must recover both
				// address families after any timeout, cancellation or failure.
				p.resolver = original
				p.Refresh(context.Background())
				checkLifetimeAnswer(t, p, true)
				if original.count() != 2 || p.Stats().UpstreamLookups != 3 {
					t.Fatal("recovery caused an unexpected lookup count")
				}
			})
		})
	}
}
