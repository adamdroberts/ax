package egress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestCompleteRangeJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/complete_range_json_cases.json")
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
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(string(tc.Wire), nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/v1", nil)
			for name, value := range tc.Headers {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("range response failed before the body check", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				err = CheckResponseBody(resp, tc.Method, body)
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			if !bytes.Equal(body, tc.Body) {
				t.Fatal("response body changed or consumed bytes were lost on rejection")
			}
			if !tc.Accepted {
				if !strings.Contains(err.Error(), "JSON interoperability policy") {
					t.Fatal("unexpected rejection reason", err)
				}
				if tc.Layout == "multipart" {
					if n, again := resp.Body.Read(make([]byte, 1)); n != 0 || again == nil {
						t.Fatal("multipart JSON rejection did not remain sticky")
					}
				}
			}
		})
	}
}

func TestCompleteRangeJSONLargeDocument(t *testing.T) {
	document := []byte(`"` + strings.Repeat("a", MaxResponseBodyBytes-1026) + `"`)
	cut := len(document) / 2
	var body []byte
	for _, first := range []int{0, cut} {
		last := cut
		if first != 0 {
			last = len(document)
		}
		body = append(body, []byte(fmt.Sprintf("--large\r\nContent-Type: application/json\r\nContent-Range: bytes %d-%d/%d\r\n\r\n", first, last-1, len(document)))...)
		body = append(body, document[first:last]...)
		body = append(body, '\r', '\n')
	}
	body = append(body, []byte("--large--\r\n")...)
	if len(body) > MaxResponseBodyBytes {
		t.Fatal("fixture exceeds the body budget")
	}
	if err := checkMultipartRanges(body, "large"); err != nil {
		t.Fatal("large complete JSON rejected", err)
	}
	body[len(body)-len("\r\n--large--\r\n")-1] = '!'
	if err := checkMultipartRanges(body, "large"); err == nil || !strings.Contains(err.Error(), "JSON interoperability policy") {
		t.Fatal("invalid final byte in complete JSON was not rejected", err)
	}
}
