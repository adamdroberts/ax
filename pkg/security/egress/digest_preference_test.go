package egress

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestDigestPreferenceMetadataContexts(t *testing.T) {
	for _, name := range []string{"Want-Content-Digest", "Want-Repr-Digest"} {
		t.Run(name+"/empty-internal-list", func(t *testing.T) {
			headers := http.Header{name: nil}
			if err := checkRequestHeaders(headers); err == nil {
				t.Fatal("empty internal request field list admitted")
			}
			resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: headers}
			if err := CheckResponse(resp); err == nil {
				t.Fatal("empty internal response field list admitted")
			}
			if err := CheckResponseBody(resp, "GET", nil); err == nil {
				t.Fatal("empty field list bypassed complete-body checks")
			}
		})
		t.Run(name+"/mime-context", func(t *testing.T) {
			metadata := responseMetadata{mimePart: true}
			if err := metadata.add(name, "not an HTTP preference dictionary"); err != nil {
				t.Fatal("HTTP preference semantics applied to MIME metadata")
			}
		})
	}
}

func TestDigestPreferenceWireAndBody(t *testing.T) {
	data, err := os.ReadFile("testdata/digest_preference_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Responses []digestCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Responses {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(string(tc.Wire), nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/digest", nil)
			for name, value := range tc.RequestHeaders {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			var body []byte
			if err == nil {
				defer resp.Body.Close()
				body, err = io.ReadAll(resp.Body)
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted {
				if !bytes.Equal(body, tc.Body) {
					t.Fatal("accepted content changed")
				}
				if err := CheckResponseBody(resp, tc.Method, body); err != nil {
					t.Fatalf("complete body: %v", err)
				}
			} else if resp != nil {
				// A failed integrity check must remain a failure on subsequent reads.
				if _, again := resp.Body.Read(make([]byte, 1)); again == nil || again == io.EOF {
					t.Fatal("integrity failure was not sticky")
				}
			}
		})
	}
}

func TestDigestPreferenceDirectTransport(t *testing.T) {
	data, err := os.ReadFile("testdata/digest_preference_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Requests []struct {
			Name      string
			Accepted  bool
			Arguments struct {
				Method, Body string
				Headers      map[string]string
			}
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Requests {
		t.Run(tc.Name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			client := newClient(mustPolicy(t, "http://api.example.com"), dns,
				pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", nil))
			req, _ := http.NewRequest(tc.Arguments.Method, "http://api.example.com/digest", strings.NewReader(tc.Arguments.Body))
			for name, value := range tc.Arguments.Headers {
				req.Header[name] = []string{value}
			}
			resp, err := client.Do(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.Accepted {
				t.Errorf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			dns.mu.Lock()
			calls := len(dns.calls)
			dns.mu.Unlock()
			if !tc.Accepted && calls != 0 {
				t.Error("invalid digest reached DNS")
			}
		})
	}
}
