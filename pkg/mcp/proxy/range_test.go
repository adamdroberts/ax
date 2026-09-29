package proxy

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Exercise both actual dispatch and the diagnostic tool against the same
// cross-runtime fixtures. No origin server is contacted by this test.
func TestRangePolicyBeforeDispatch(t *testing.T) {
	data, err := os.ReadFile("../../security/httpguard/testdata/range_cases.json")
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
			if result.IsError == tc.Accepted || (*calls == 1) != tc.Accepted {
				t.Fatalf("accepted=%v result_error=%v dispatches=%d", tc.Accepted, result.IsError, *calls)
			}
			if got := diagnosticResult(t, s, tc.Arguments); got["blocked"] != !tc.Accepted {
				t.Fatal("diagnostic disagrees with range policy", got)
			}
		})
	}
}
