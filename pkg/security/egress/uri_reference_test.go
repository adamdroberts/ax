package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type uriReferenceCase struct {
	Name     string
	Headers  [][2]string
	Accepted bool
}

func uriReferenceCases(t *testing.T) []uriReferenceCase {
	t.Helper()
	data, err := os.ReadFile("testdata/uri_reference_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Responses []uriReferenceCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Responses
}

func TestURIReferenceParsedContract(t *testing.T) {
	for _, tc := range uriReferenceCases(t) {
		for _, stage := range []string{"parsed", "complete"} {
			t.Run(tc.Name+"/"+stage, func(t *testing.T) {
				if stage == "complete" && strings.HasSuffix(tc.Name, "-connection") {
					t.Skip("Connection belongs to the header-stage contract")
				}
				resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: 2, Header: http.Header{}}
				for _, field := range tc.Headers {
					resp.Header.Add(field[0], field[1])
				}
				var err error
				if stage == "parsed" {
					err = CheckResponse(resp)
				} else {
					err = CheckResponseBody(resp, "GET", []byte("ok"))
				}
				if (err == nil) != tc.Accepted {
					t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
				}
			})
		}
	}
}

func TestURIReferenceWireContract(t *testing.T) {
	for _, tc := range uriReferenceCases(t) {
		for _, stage := range []string{"final", "interim"} {
			t.Run(tc.Name+"/"+stage, func(t *testing.T) {
				var fields strings.Builder
				for _, field := range tc.Headers {
					fields.WriteString(field[0] + ": " + field[1] + "\r\n")
				}
				wire := "HTTP/1.1 200 OK\r\n" + fields.String() + "Content-Length: 2\r\n\r\nok"
				if stage == "interim" {
					wire = "HTTP/1.1 103 Early Hints\r\n" + fields.String() + "\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				}
				client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
				resp, err := client.Get("http://api.example.com/metadata")
				if resp != nil {
					defer resp.Body.Close()
				}
				if (err == nil) != tc.Accepted {
					t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
				}
				if tc.Accepted {
					body, err := io.ReadAll(resp.Body)
					if err != nil || string(body) != "ok" {
						t.Fatalf("body changed: %q %v", body, err)
					}
				}
			})
		}
	}
}

func TestURIReferenceDirectRequest(t *testing.T) {
	data, err := os.ReadFile("testdata/uri_reference_cases.json")
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
			client := newClient(mustPolicy(t, "http://api.example.com"), dns, pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", func(sent *http.Request) {
				if sent.Host != "api.example.com" || sent.URL.RequestURI() != "/metadata" {
					t.Error("reference metadata changed the actual destination")
				}
				for field, value := range tc.Arguments.Headers {
					if sent.Header.Get(field) != value {
						t.Error("reference metadata was decoded or changed")
					}
				}
			}))
			req, _ := http.NewRequest(tc.Arguments.Method, "http://api.example.com/metadata", strings.NewReader(tc.Arguments.Body))
			for k, v := range tc.Arguments.Headers {
				req.Header[k] = []string{v}
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
				t.Error("invalid metadata reached DNS")
			}
		})
	}
}

func TestURIReferenceMetadataContexts(t *testing.T) {
	for _, field := range []string{"Location", "Content-Location"} {
		t.Run(field+"/empty-values", func(t *testing.T) {
			resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: 2, Header: http.Header{field: []string{}}}
			if CheckResponse(resp) == nil || CheckResponseBody(resp, "GET", []byte("ok")) == nil {
				t.Fatal("empty internal field values bypassed validation")
			}
		})
		t.Run(field+"/mime", func(t *testing.T) {
			body := "--b\r\nContent-Range: bytes 0-0/1\r\n" + field + ": (comment) /part (comment)\r\n\r\na\r\n--b--\r\n"
			if err := checkMultipartRanges([]byte(body), "b"); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, values := range [][]string{{}, {"/one", "/two"}} {
		name := "request-empty-values"
		if len(values) != 0 {
			name = "request-repeated-values"
		}
		t.Run(name, func(t *testing.T) {
			dns := fakeDNS("8.8.8.8")
			client := newClient(mustPolicy(t, "http://api.example.com"), dns, pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", nil))
			req, _ := http.NewRequest("POST", "http://api.example.com/metadata", nil)
			req.Header["Content-Location"] = values
			resp, err := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			dns.mu.Lock()
			calls := len(dns.calls)
			dns.mu.Unlock()
			if err == nil || calls != 0 {
				t.Fatalf("invalid internal request fields reached dispatch: error=%v DNS calls=%d", err, calls)
			}
		})
	}
}
