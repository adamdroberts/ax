package egress

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestMultipartContentConsistency(t *testing.T) {
	data, err := os.ReadFile("testdata/multipart_consistency_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method string
			Accepted     bool
			Headers      map[string]string `json:"request_headers"`
			Wire         string            `json:"wire_base64"`
			Body         string            `json:"body_base64"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			wire, err := base64.StdEncoding.DecodeString(tc.Wire)
			if err != nil {
				t.Fatal(err)
			}
			wantBody, err := base64.StdEncoding.DecodeString(tc.Body)
			if err != nil {
				t.Fatal(err)
			}
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(string(wire), nil))
			req, err := http.NewRequest(tc.Method, "http://api.example.com/v1", nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range tc.Headers {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("valid response metadata rejected before body: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted && string(body) != string(wantBody) {
				t.Fatal("validated response content changed")
			}
			if !tc.Accepted {
				if !strings.Contains(err.Error(), "conflicting multipart byte ranges") {
					t.Fatalf("rejected for unexpected reason: %v", err)
				}
				if n, repeated := resp.Body.Read(make([]byte, 1)); n != 0 || repeated == nil {
					t.Fatal("inconsistent response accepted after the first error")
				}
			}
		})
	}
}

func TestMultipartContentConsistencyLargeOverlaps(t *testing.T) {
	// Exercise the maximum part count near the whole-response byte budget.
	// The last byte of the last part is the only difference in the denial case.
	size := (MaxResponseBodyBytes - 4096) / 16
	part := fmt.Sprintf("--large\r\nContent-Range: bytes 0-%d/*\r\n\r\n%s\r\n", size-1, strings.Repeat("a", size))
	body := []byte(strings.Repeat(part, 16) + "--large--\r\n")
	if len(body) > MaxResponseBodyBytes {
		t.Fatal("test fixture exceeds the response budget")
	}
	if err := checkMultipartRanges(body, "large"); err != nil {
		t.Fatal("consistent large overlaps rejected", err)
	}
	body[16*len(part)-3] = '!'
	if err := checkMultipartRanges(body, "large"); err == nil || !strings.Contains(err.Error(), "conflicting multipart byte ranges") {
		t.Fatal("late conflict in large overlaps accepted", err)
	}
}
