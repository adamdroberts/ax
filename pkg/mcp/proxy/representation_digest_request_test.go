package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/ax/pkg/security/snort"
)

func TestRepresentationDigestBeforeInspectionAndDispatch(t *testing.T) {
	data, err := os.ReadFile("../../security/egress/testdata/representation_digest_cases.json")
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
