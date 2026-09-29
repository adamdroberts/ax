package egress

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/ax/pkg/security/httpguard"
)

func TestRequestDigestDirectTransport(t *testing.T) {
	data, err := os.ReadFile("../httpguard/testdata/request_digest_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string
			Accepted  bool
			Arguments struct {
				Method, Body string
				Headers      map[string]string
			}
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			client := newClient(mustPolicy(t, "http://api.example.com"), dns,
				pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", nil))
			req, _ := http.NewRequest(tc.Arguments.Method, "http://api.example.com/digest", strings.NewReader(tc.Arguments.Body))
			for name, value := range tc.Arguments.Headers {
				req.Header[name] = []string{value}
			}
			resp, err := client.Do(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.Accepted {
				t.Errorf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			dns.mu.Lock()
			calls := len(dns.calls)
			dns.mu.Unlock()
			if !tc.Accepted && calls != 0 {
				t.Error("invalid digest reached DNS")
			}
		})
	}
}

func requestDigestValue(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

type digestProbeBody struct {
	io.Reader
	readErr error
	read    atomic.Int64
	closed  atomic.Int64
}

func (b *digestProbeBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read.Add(int64(n))
	if b.readErr != nil {
		err = b.readErr
	}
	return n, err
}
func (b *digestProbeBody) Close() error { b.closed.Add(1); return nil }

func TestRequestDigestStreamLifecycle(t *testing.T) {
	const limit = httpguard.MaxRequestBodyBytes
	maximum := strings.Repeat("x", limit)
	largeHash := sha512.Sum512([]byte("hello"))
	good, empty := requestDigestValue("hello"), requestDigestValue("")
	for _, tc := range []struct {
		name, body string
		length     int64
		values     []string
		accepted   bool
		noBody     bool
		readError  bool
	}{
		{"known-maximum", maximum, limit, []string{requestDigestValue(maximum)}, true, false, false},
		{"unknown-maximum", maximum, -1, []string{requestDigestValue(maximum)}, true, false, false},
		{"known-oversize", maximum + "x", limit + 1, []string{good}, false, false, false},
		{"unknown-oversize", maximum + "x", -1, []string{good}, false, false, false},
		{"declared-short", "hello", 4, []string{good}, false, false, false},
		{"declared-long", "hello", 6, []string{good}, false, false, false},
		{"zero-means-unknown", "hello", 0, []string{good}, true, false, false},
		{"negative-one-means-unknown", "hello", -1, []string{good}, true, false, false},
		{"invalid-negative-length", "hello", -2, []string{good}, false, false, false},
		{"empty-reader", "", 0, []string{empty}, true, false, false},
		{"nil-body", "", 0, []string{empty}, true, true, false},
		{"nil-body-positive-length", "", 5, []string{empty}, false, true, false},
		{"nil-body-mismatch", "", 0, []string{good}, false, true, false},
		{"read-error-with-bytes", "hello", 5, []string{good}, false, false, true},
		{"read-error-without-bytes", "", 0, []string{empty}, false, false, true},
		{"repeated-strong-fields", "hello", 5, []string{good, "sha-512=:" + base64.StdEncoding.EncodeToString(largeHash[:]) + ":"}, true, false, false},
		{"duplicate-algorithm-across-fields", "hello", 5, []string{good, good}, false, false, false},
		{"empty-internal-value-list", "hello", 5, nil, false, false, false},
		{"malformed-before-body-read", "hello", 5, []string{"sha-256=:bad!:"}, false, false, false},
		{"actual-body-mismatch-replay-would-match", "other", 5, []string{good}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			sent := make(chan string, 1)
			client := newClient(mustPolicy(t, "http://api.example.com"), dns,
				func(context.Context, string, string) (net.Conn, error) {
					left, right := net.Pipe()
					go func() {
						defer right.Close()
						right.SetDeadline(time.Now().Add(5 * time.Second))
						req, err := http.ReadRequest(bufio.NewReader(right))
						if err != nil {
							return
						}
						body, err := io.ReadAll(req.Body)
						req.Body.Close()
						if err != nil {
							return
						}
						sent <- string(body)
						io.WriteString(right, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					}()
					return left, nil
				})
			req, _ := http.NewRequest("POST", "http://api.example.com/digest", nil)
			probe := &digestProbeBody{Reader: strings.NewReader(tc.body)}
			if tc.readError {
				probe.readErr = errors.New("synthetic body failure")
			}
			if !tc.noBody {
				req.Body = probe
			}
			req.ContentLength = tc.length
			req.Header["Content-Digest"] = tc.values
			replayed := 0
			req.GetBody = func() (io.ReadCloser, error) {
				replayed++
				return io.NopCloser(strings.NewReader("hello")), nil
			}
			resp, err := client.Do(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.accepted, err)
			}
			if replayed != 0 || !tc.noBody && probe.closed.Load() != 1 || probe.read.Load() > limit+1 {
				t.Fatal("request stream ownership, replay, or read bound violated")
			}
			if tc.name == "known-oversize" || tc.name == "malformed-before-body-read" {
				if probe.read.Load() != 0 {
					t.Fatal("invalid metadata consumed the body")
				}
			}
			dns.mu.Lock()
			calls := len(dns.calls)
			dns.mu.Unlock()
			if tc.accepted {
				select {
				case content := <-sent:
					if content != tc.body {
						t.Fatal("sent content differs from verified actual stream")
					}
				default:
					t.Fatal("accepted content was not sent")
				}
			} else if calls != 0 {
				t.Fatal("unverified content reached DNS")
			}
		})
	}
}

type digestBlockingBody struct {
	entered, released chan struct{}
	enter, closeOnce  sync.Once
	closed            atomic.Int64
}

func (b *digestBlockingBody) Read([]byte) (int, error) {
	b.enter.Do(func() { close(b.entered) })
	<-b.released
	return 0, errors.New("body closed")
}
func (b *digestBlockingBody) Close() error {
	b.closed.Add(1)
	b.closeOnce.Do(func() { close(b.released) })
	return nil
}

func TestRequestDigestCancellation(t *testing.T) {
	for _, alreadyCanceled := range []bool{false, true} {
		name := "during-read"
		if alreadyCanceled {
			name = "before-read"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &digestBlockingBody{entered: make(chan struct{}), released: make(chan struct{})}
			req, _ := http.NewRequestWithContext(ctx, "POST", "http://api.example.com", nil)
			req.Body = body
			req.ContentLength = -1
			req.Header.Set("Content-Digest", requestDigestValue(""))
			dns := fakeDNS("8.8.8.8")
			client := newClient(mustPolicy(t, "http://api.example.com"), dns, pipeResponse("", nil))
			if alreadyCanceled {
				cancel()
			}
			finished := make(chan error, 1)
			go func() {
				_, err := client.Do(req)
				finished <- err
			}()
			if !alreadyCanceled {
				select {
				case <-body.entered:
					cancel()
				case <-time.After(3 * time.Second):
					body.Close()
					t.Fatal("digest body was not read")
				}
			}
			select {
			case err := <-finished:
				if err == nil || body.closed.Load() != 1 {
					t.Fatal("cancellation did not reject and close exactly once")
				}
			case <-time.After(3 * time.Second):
				body.Close()
				t.Fatal("cancellation did not unblock the body")
			}
			dns.mu.Lock()
			calls := len(dns.calls)
			dns.mu.Unlock()
			if calls != 0 {
				t.Fatal("canceled body reached DNS")
			}
		})
	}
}
