package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConditionalResponseMetadata(t *testing.T) {
	data, err := os.ReadFile("../httpguard/testdata/conditional_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Wire string
			Accepted   bool
		} `json:"response_cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(tc.Wire, nil))
			req, _ := http.NewRequest("GET", "http://api.example.com/v1", nil)
			resp, err := client.Do(req)
			var body []byte
			if err == nil {
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted && string(body) != "ok" {
				t.Fatal("validated response content changed")
			}
		})
	}
}

func TestConditionalTransportRejectsBeforeDNS(t *testing.T) {
	for _, field := range []struct{ name, valid, invalid string }{
		{"If-Match", `"v1"`, `*,"v1"`},
		{"If-None-Match", `"v1"`, `"v1" "v2"`},
		{"If-Range", `"v1"`, `W/"v1"`},
		{"If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT", "tomorrow"},
		{"If-Unmodified-Since", "Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 31 Nov 1994 08:49:37 GMT"},
		{"Date", "Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT"},
	} {
		variants := []string{"repeated-values", "empty-values", "repeated-casing", "invalid-value"}
		if field.name == "If-Range" {
			variants = append(variants, "missing-range", "head-method")
		}
		for _, variant := range variants {
			t.Run(field.name+"/"+variant, func(t *testing.T) {
				headers := http.Header{field.name: {field.valid}, "Range": {"bytes=0-1"}}
				method := "GET"
				switch variant {
				case "repeated-values":
					headers[field.name] = []string{field.valid, field.valid}
				case "empty-values":
					headers[field.name] = nil
				case "repeated-casing":
					headers[strings.ToLower(field.name)] = []string{field.valid}
				case "invalid-value":
					headers[field.name] = []string{field.invalid}
				case "missing-range":
					delete(headers, "Range")
				case "head-method":
					method = "HEAD"
				}
				dns := fakeDNS("8.8.8.8")
				var dials atomic.Int32
				client := newClient(mustPolicy(t, "http://api.example.com"), dns, func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, fmt.Errorf("unexpected dial")
				})
				req, _ := http.NewRequest(method, "http://api.example.com/v1", nil)
				req.Header = headers
				if _, err := client.Do(req); err == nil || len(dns.calls) != 0 || dials.Load() != 0 {
					t.Fatalf("conditional reached network: error=%v DNS=%d dials=%d", err, len(dns.calls), dials.Load())
				}
			})
		}
	}
}

func TestConditionalTransportPreservesValues(t *testing.T) {
	for _, headers := range []http.Header{
		{"If-Match": {`"a,b", W/"c\d"`}},
		{"If-Range": {`"v1"`}, "Range": {"bytes=0-1"}},
		{"Date": {"Sat, 31 Dec 2016 23:59:60 GMT"}, "If-Modified-Since": {"Sun, 06 Nov 1994 08:49:37 GMT"}},
	} {
		sent := make(chan http.Header, 1)
		client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"),
			pipeResponse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", func(req *http.Request) { sent <- req.Header }))
		req, _ := http.NewRequest("GET", "http://api.example.com/v1", nil)
		req.Header = headers
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		received := <-sent
		for name, values := range headers {
			if len(received.Values(name)) != 1 || received.Get(name) != values[0] {
				t.Fatal("transport changed a validated conditional field")
			}
		}
	}
}
