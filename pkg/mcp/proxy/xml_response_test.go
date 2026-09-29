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

func TestXMLResponsesBeforeToolDelivery(t *testing.T) {
	data, err := os.ReadFile("../../security/egress/testdata/xml_response_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name     string
			Document []byte `json:"document_base64"`
			Accepted bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://api.example.com")
			s.httpClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
				*calls++
				return &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"application/xml"}}, ContentLength: int64(len(tc.Document)), Body: io.NopCloser(bytes.NewReader(tc.Document)), Request: req}, nil
			})}
			result, rpcErr := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://api.example.com/xml"})
			if rpcErr != nil || *calls != 1 {
				t.Fatalf("dispatch failed: calls=%d error=%v", *calls, rpcErr)
			}
			if !result.IsError != tc.Accepted {
				t.Fatalf("accepted=%v want=%v", !result.IsError, tc.Accepted)
			}
			if tc.Accepted {
				var value struct{ Body string }
				if err := json.Unmarshal([]byte(result.Content[0].Text), &value); err != nil || !bytes.Equal([]byte(value.Body), tc.Document) {
					t.Fatal("response bytes changed")
				}
			}
			if atomic.LoadUint64(&s.responseBytes) != uint64(len(tc.Document)) {
				t.Fatal("response bytes were not charged")
			}
		})
	}
}
