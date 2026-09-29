package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestContentRangeWireResponses(t *testing.T) {
	data, err := os.ReadFile("testdata/content_range_responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method, Wire, Body string
			Accepted                 bool
			Headers                  map[string]string `json:"request_headers"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(tc.Wire, nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/v1", nil)
			for name, value := range tc.Headers {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			var body []byte
			if err == nil {
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted && string(body) != tc.Body {
				t.Fatal("validated response content changed")
			}
		})
	}
}

func TestContentRangeTransportRejectsBeforeDNS(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		headers      http.Header
		length       int64
		noBody       bool
	}{
		{"duplicate-values", "PUT", http.Header{"Content-Range": {"bytes 0-1/4", "bytes 0-1/4"}}, 2, false},
		{"duplicate-casing", "PUT", http.Header{"Content-Range": {"bytes 0-1/4"}, "content-range": {"bytes 0-1/4"}}, 2, false},
		{"empty-values", "PUT", http.Header{"Content-Range": {}}, 2, false},
		{"post", "POST", http.Header{"Content-Range": {"bytes 0-1/4"}}, 2, false},
		{"short", "PUT", http.Header{"Content-Range": {"bytes 0-1/4"}}, 1, false},
		{"long", "PUT", http.Header{"Content-Range": {"bytes 0-1/4"}}, 3, false},
		{"unknown-length", "PUT", http.Header{"Content-Range": {"bytes 0-1/4"}}, -1, false},
		{"missing-body", "PUT", http.Header{"Content-Range": {"bytes 0-1/4"}}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			var dials atomic.Int32
			client := newClient(mustPolicy(t, "http://api.example.com"), dns, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, fmt.Errorf("unexpected dial")
			})
			req, _ := http.NewRequest(tc.method, "http://api.example.com/v1", strings.NewReader("ab"))
			req.Header, req.ContentLength = tc.headers, tc.length
			if tc.noBody {
				req.Body = nil
			}
			if _, err := client.Do(req); err == nil || len(dns.calls) != 0 || dials.Load() != 0 {
				t.Fatalf("partial upload reached network: error=%v DNS=%d dials=%d", err, len(dns.calls), dials.Load())
			}
		})
	}
}

func TestContentRangeTransportPreservesUpload(t *testing.T) {
	for _, body := range []string{"ab", "€"} {
		value := fmt.Sprintf("bytes 10-%d/*", 10+len(body)-1)
		sent := make(chan string, 1)
		client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"),
			func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					server.SetDeadline(time.Now().Add(5 * time.Second))
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return
					}
					content, err := io.ReadAll(req.Body)
					req.Body.Close()
					if err != nil || req.Method != "PUT" || req.ContentLength != int64(len(body)) || req.Header.Get("Content-Range") != value {
						sent <- "invalid upload metadata"
					} else {
						sent <- string(content)
					}
					io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}()
				return client, nil
			})
		req, _ := http.NewRequest("PUT", "http://api.example.com/v1", strings.NewReader(body))
		req.Header.Set("Content-Range", value)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || <-sent != body {
			t.Fatal("transport changed the inspected upload", err)
		}
	}
}

func TestMultipartRangeHeaderBudgets(t *testing.T) {
	part := func(extra string) string {
		return "--b\r\nContent-Range: bytes 0-1/8\r\n" + extra + "\r\nab\r\n"
	}
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"field-limit", part("X: "+strings.Repeat("a", 8192-5)+"\r\n") + "--b--", true},
		{"field-over", part("X: "+strings.Repeat("a", 8192-4)+"\r\n") + "--b--", false},
		{"count-limit", part(strings.Repeat("X: v\r\n", 127)) + "--b--", true},
		{"count-over", part(strings.Repeat("X: v\r\n", 128)) + "--b--", false},
		{"aggregate-count", part(strings.Repeat("X: v\r\n", 63)) + part(strings.Repeat("Y: v\r\n", 64)) + "--b--", false},
		{"aggregate-bytes", part(strings.Repeat("X: "+strings.Repeat("a", 8100)+"\r\n", 4)) + part(strings.Repeat("Y: "+strings.Repeat("b", 8100)+"\r\n", 5)) + "--b--", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkMultipartRanges([]byte(tc.body), "b"); (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.accepted, err)
			}
		})
	}
}
