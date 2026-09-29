package proxy

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestContentRangeUploadsBeforeDispatch(t *testing.T) {
	data, err := os.ReadFile("../../security/httpguard/testdata/content_range_requests.json")
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
			s, calls := protocolTestServer(t, "https://api.example.com")
			result, _ := s.executeHTTPRequest(context.Background(), tc.Arguments)
			wantCalls := 0
			if tc.Accepted {
				wantCalls = 1
			}
			if result.IsError == tc.Accepted || *calls != wantCalls {
				t.Fatalf("accepted=%v result_error=%v dispatches=%d", tc.Accepted, result.IsError, *calls)
			}
			if got := diagnosticResult(t, s, tc.Arguments); got["blocked"] != !tc.Accepted {
				t.Fatal("diagnostic disagrees with upload policy", got)
			}
		})
	}
}
