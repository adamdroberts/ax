package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRangeTransportRejectsBeforeDNS(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		headers      http.Header
	}{
		{"empty-field", "GET", http.Header{"Range": {""}}},
		{"empty-values", "GET", http.Header{"Range": {}}},
		{"missing-dash", "GET", http.Header{"Range": {"bytes=1"}}},
		{"reversed", "GET", http.Header{"Range": {"bytes=1-0"}}},
		{"duplicate-values", "GET", http.Header{"Range": {"bytes=0-1", "bytes=4-5"}}},
		{"duplicate-casing", "GET", http.Header{"Range": {"bytes=0-1"}, "range": {"bytes=4-5"}}},
		{"repeated-ranges", "GET", http.Header{"Range": {"bytes=0-999,0-999,0-999"}}},
		{"overflow", "GET", http.Header{"Range": {"bytes=18446744073709551616-"}}},
		{"unknown-unit", "GET", http.Header{"Range": {"items=0-1"}}},
		{"too-many-members", "GET", http.Header{"Range": {"bytes=" + strings.Repeat(",", 16) + "0-1"}}},
		{"head", "HEAD", http.Header{"rAnGe": {"bytes=0-1"}}},
		{"post", "POST", http.Header{"Range": {"bytes=0-1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			var dials atomic.Int32
			client := newClient(mustPolicy(t, "http://api.example.com"), dns, func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, fmt.Errorf("unexpected dial")
			})
			req, err := http.NewRequest(tc.method, "http://api.example.com/v1", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = tc.headers
			if _, err := client.Do(req); err == nil || len(dns.calls) != 0 || dials.Load() != 0 {
				t.Fatalf("range reached network: error=%v DNS=%d dials=%d", err, len(dns.calls), dials.Load())
			}
		})
	}
}

func TestRangeTransportPreservesValidField(t *testing.T) {
	for _, value := range []string{"bytes=0-1", "bytes=0-1,4-5", "BYTES=,000-001,", "bytes=4-", "bytes=-2", "bytes=" + strings.Repeat("0", 5000) + "1-2"} {
		// A fake byte stream, rather than a public origin, verifies the exact
		// request emitted by the real guarded HTTP transport.
		requests := make(chan *http.Request, 1)
		client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"),
			pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", func(req *http.Request) { requests <- req }))
		req, _ := http.NewRequest("GET", "http://api.example.com/v1", nil)
		req.Header.Set("Range", value)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("valid range rejected", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "ok" {
			t.Fatal(body, err)
		}
		sent := <-requests
		if sent.Method != "GET" || len(sent.Header.Values("Range")) != 1 || sent.Header.Get("Range") != value {
			t.Fatal("transport changed inspected Range field")
		}
	}
}
