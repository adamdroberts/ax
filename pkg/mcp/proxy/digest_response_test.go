package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
)

func TestContentDigestBeforeToolDelivery(t *testing.T) {
	data, err := os.ReadFile("../../security/egress/testdata/content_digest_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method      string
			Status            int
			RequestHeaders    map[string]string `json:"request_headers"`
			Headers           [][2]string
			Body              []byte `json:"body_base64"`
			Accepted, Interim bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		if tc.Interim || tc.Name == "connection-nomination" {
			continue
		} // Header-stage controls use the production wire path.
		t.Run(tc.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://api.example.com")
			s.httpClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
				*calls++
				h := http.Header{}
				for _, field := range tc.Headers {
					h.Add(field[0], field[1])
				}
				return &http.Response{StatusCode: tc.Status, ProtoMajor: 1, ProtoMinor: 1, Header: h, ContentLength: int64(len(tc.Body)), Body: io.NopCloser(bytes.NewReader(tc.Body)), Request: req}, nil
			})}
			headers := map[string]any{}
			for name, value := range tc.RequestHeaders {
				headers[name] = value
			}
			result, rpcErr := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://api.example.com/digest", "method": tc.Method, "headers": headers})
			if rpcErr != nil || *calls != 1 {
				t.Fatalf("dispatch failed: %v calls=%d", rpcErr, *calls)
			}
			if !result.IsError != tc.Accepted {
				t.Fatalf("accepted=%v want=%v", !result.IsError, tc.Accepted)
			}
			if tc.Accepted {
				var value struct{ Body string }
				if err := json.Unmarshal([]byte(result.Content[0].Text), &value); err != nil || !bytes.Equal([]byte(value.Body), tc.Body) {
					t.Fatal("accepted content changed")
				}
			}
			if atomic.LoadUint64(&s.responseBytes) != uint64(len(tc.Body)) {
				t.Fatal("consumed content was not charged")
			}
		})
	}
}
