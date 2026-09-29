package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestResponseRangeCorrelation(t *testing.T) {
	data, err := os.ReadFile("testdata/response_range_correlation_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method, Wire, Body string
			Accepted                 bool
			Headers                  map[string]string `json:"request_headers"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(tc.Wire, nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/v1", nil)
			for name, value := range tc.Headers {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			var body []byte
			if err == nil {
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted && string(body) != tc.Body {
				t.Fatal("validated response content changed")
			}
		})
	}
}
