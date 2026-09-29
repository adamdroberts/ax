package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/ax/pkg/security/egress"
)

func TestJSONResponsesBeforeToolDelivery(t *testing.T) {
	testJSONResponseCases(t, "testdata/response_json_cases.json", false)
}

func TestCompleteSingleRangeJSONBeforeToolDelivery(t *testing.T) {
	testJSONResponseCases(t, "../../security/egress/testdata/complete_range_json_cases.json", true)
}

func testJSONResponseCases(t *testing.T, path string, singleOnly bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method, Layout string
			Accepted             bool
			Headers              map[string]string `json:"request_headers"`
			Wire                 []byte            `json:"wire_base64"`
			Body                 []byte            `json:"body_base64"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		if singleOnly && tc.Layout != "single" {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://api.example.com")
			s.httpClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
				*calls++
				resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(tc.Wire)), req)
				if err == nil {
					if err = egress.CheckResponse(resp); err != nil {
						resp.Body.Close()
						return nil, err
					}
				}
				return resp, err
			})}
			headers := map[string]any{}
			for name, value := range tc.Headers {
				headers[name] = value
			}
			result, rpcErr := s.executeHTTPRequest(context.Background(), map[string]any{
				"url": "https://api.example.com/v1", "method": tc.Method, "headers": headers,
			})
			if rpcErr != nil || *calls != 1 {
				t.Fatalf("response test did not reach transport: calls=%d error=%v", *calls, rpcErr)
			}
			var output map[string]json.RawMessage
			parseErr := json.Unmarshal([]byte(result.Content[0].Text), &output)
			body, delivered := output["body"]
			accepted := parseErr == nil && delivered
			if accepted != tc.Accepted {
				t.Fatalf("accepted=%v want=%v", accepted, tc.Accepted)
			}
			if accepted {
				var actual string
				if err := json.Unmarshal(body, &actual); err != nil || !bytes.Equal([]byte(actual), tc.Body) {
					t.Fatal("response bytes changed before tool delivery")
				}
			} else if !result.IsError {
				t.Fatal("rejected response did not report a tool error")
			}
			if got := atomic.LoadUint64(&s.responseBytes); got != uint64(len(tc.Body)) {
				t.Fatalf("response budget charged %d bytes, want %d", got, len(tc.Body))
			}
		})
	}
}
