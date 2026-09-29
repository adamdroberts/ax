package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestURIReferenceBeforeInspectionAndDispatch(t *testing.T) {
	data, err := os.ReadFile("../../security/egress/testdata/uri_reference_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Requests []struct {
			Name      string
			Accepted  bool
			Arguments map[string]any
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Requests {
		t.Run(tc.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://api.example.com")
			result, rpcErr := s.executeHTTPRequest(context.Background(), tc.Arguments)
			if rpcErr != nil || result.IsError == tc.Accepted || (*calls == 1) != tc.Accepted {
				t.Errorf("accepted=%v want=%v dispatches=%d rpc=%v", !result.IsError, tc.Accepted, *calls, rpcErr)
			}
			if got := diagnosticResult(t, s, tc.Arguments); got["blocked"] != !tc.Accepted {
				t.Error("diagnostic differs from admission")
			}
			if !tc.Accepted && s.inspectionBytes != 0 {
				t.Error("invalid URI metadata reached inspection")
			}
		})
	}
}

func TestURIReferenceBeforeToolDelivery(t *testing.T) {
	data, err := os.ReadFile("../../security/egress/testdata/uri_reference_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Responses []struct {
			Name     string
			Headers  [][2]string
			Accepted bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Responses {
		if strings.HasSuffix(tc.Name, "-connection") {
			continue // Connection nomination is checked by the production wire path.
		}
		t.Run(tc.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://api.example.com")
			s.httpClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
				*calls++
				h := http.Header{}
				for _, field := range tc.Headers {
					h.Add(field[0], field[1])
				}
				return &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: h, ContentLength: 2, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
			})}
			result, rpcErr := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://api.example.com/metadata", "method": "GET"})
			if rpcErr != nil || *calls != 1 {
				t.Fatalf("dispatch failed: %v calls=%d", rpcErr, *calls)
			}
			var value struct {
				Body       string
				StatusCode int `json:"status_code"`
			}
			delivered := json.Unmarshal([]byte(result.Content[0].Text), &value) == nil && value.StatusCode == 200
			if delivered != tc.Accepted {
				t.Fatalf("delivered=%v want=%v", delivered, tc.Accepted)
			}
			if delivered && value.Body != "ok" {
				t.Fatal("accepted body changed")
			}
		})
	}
}
