package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/ax/pkg/security/snort"
)

func TestRequestDigestBeforeInspectionAndDispatch(t *testing.T) {
	data, err := os.ReadFile("../../security/httpguard/testdata/request_digest_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string
			Accepted  bool
			Arguments map[string]any
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			calls := 0
			s, err := NewServer(WithEngine(snort.NewEngine()), WithAllowedOrigins("https://api.example.com"),
				WithHTTPClient(&http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					var body []byte
					if req.Body != nil {
						body, err = io.ReadAll(req.Body)
						req.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
					}
					if string(body) != tc.Arguments["body"] {
						t.Error("dispatched content differs from verified content")
					}
					responseBody := "ok"
					if req.Method == "HEAD" {
						responseBody = ""
					}
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
				})}))
			if err != nil {
				t.Fatal(err)
			}
			result, _ := s.executeHTTPRequest(context.Background(), tc.Arguments)
			if result.IsError == tc.Accepted || (calls == 1) != tc.Accepted {
				t.Errorf("accepted=%v want=%v dispatches=%d", !result.IsError, tc.Accepted, calls)
			}
			if got := diagnosticResult(t, s, tc.Arguments); got["blocked"] != !tc.Accepted {
				t.Error("diagnostic differs from request admission")
			}
			if !tc.Accepted && s.inspectionBytes != 0 {
				t.Error("invalid digest reached signature inspection")
			}
		})
	}
}

func TestRequestDigestStillSubjectToSignatures(t *testing.T) {
	s, calls := protocolTestServer(t, "https://api.example.com")
	if _, err := s.engine.LoadRulesFromReader(strings.NewReader(
		"drop tcp any any -> any any (content:\"forbidden-marker\"; sid:1;)")); err != nil {
		t.Fatal(err)
	}
	body := "forbidden-marker"
	hash := sha256.Sum256([]byte(body))
	args := map[string]any{"url": "https://api.example.com", "method": "POST", "body": body,
		"headers": map[string]any{"Content-Digest": "sha-256=:" + base64.StdEncoding.EncodeToString(hash[:]) + ":"}}
	result, _ := s.executeHTTPRequest(context.Background(), args)
	if !result.IsError || *calls != 0 || s.inspectionBytes == 0 {
		t.Fatal("valid digest bypassed signature enforcement")
	}
	if got := diagnosticResult(t, s, args); got["blocked"] != true || got["rule_sid"] != float64(1) {
		t.Fatal("diagnostic did not apply the blocking signature")
	}
}
