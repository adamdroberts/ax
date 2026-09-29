package httpguard

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestHTTPDateCenturyBoundaries(t *testing.T) {
	data, err := os.ReadFile("testdata/http_date_boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Now, Value string
			Accepted         bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, tc.Now)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateHTTPDateAt(tc.Value, true, now); (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
		})
	}
}
