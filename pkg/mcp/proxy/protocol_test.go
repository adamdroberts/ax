package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/ax/pkg/security/snort"
)

func TestSharedProtocolCases(t *testing.T) {
	data, err := os.ReadFile("../../security/httpguard/testdata/request_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string
			Accepted  bool
			Arguments map[string]any
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, _, _, err := buildHTTPRequest(context.Background(), tc.Arguments)
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v error=%v", tc.Accepted, err)
			}
		})
	}
}

func TestMalformedRequestMediaParameterNeverDispatches(t *testing.T) {
	s, calls := protocolTestServer(t, "https://api.example.com")
	for _, media := range []string{
		"text/plain; charset =utf-8",
		"text/plain; charset= utf-8",
		`application/json; charset = "utf-8"`,
	} {
		args := map[string]any{
			"url": "https://api.example.com/v1", "method": "POST", "body": "{}",
			"headers": map[string]any{"Content-Type": media},
		}
		if result, _ := s.executeHTTPRequest(context.Background(), args); !result.IsError {
			t.Errorf("accepted malformed media parameter %q", media)
		}
		if got := diagnosticResult(t, s, args); got["blocked"] != true {
			t.Errorf("diagnostic accepted malformed media parameter %q", media)
		}
	}
	if *calls != 0 {
		t.Fatalf("malformed request media parameters reached transport %d times", *calls)
	}
}

func TestDNSOverHTTPNeverReachesApprovedOriginTransport(t *testing.T) {
	data, err := os.ReadFile("../../security/snort/testdata/rule_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method, URL, Body, Profile string
			Headers                          map[string]string
			Match                            bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range corpus.Cases {
		if !c.Match || !strings.HasPrefix(c.Name, "DNS escape ") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			s, calls := protocolTestServer(t, "https://service.example", "https://service.example:853", "https://[2606:4700:4700::1111]:853")
			s.engine, err = snort.NewProfileEngine(c.Profile)
			if err != nil {
				t.Fatal(err)
			}
			headers := map[string]any{}
			for key, value := range c.Headers {
				headers[key] = value
			}
			args := map[string]any{"method": c.Method, "url": c.URL, "body": c.Body, "headers": headers}
			result, _ := s.executeHTTPRequest(context.Background(), args)
			if !result.IsError || *calls != 0 {
				t.Fatalf("DNS escape reached transport: %+v calls=%d", result, *calls)
			}
			if got := diagnosticResult(t, s, args); got["blocked"] != true {
				t.Fatal("diagnostic disagrees with dispatch", got)
			}
		})
		checked++
	}
	if checked < 24 {
		t.Fatal("missing DNS escape fixtures", checked)
	}
	s, calls := protocolTestServer(t, "https://service.example")
	s.engine, err = snort.NewProfileEngine("strict")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://service.example/v1/status"})
	if result.IsError || *calls != 1 {
		t.Fatal("ordinary approved request failed", result, *calls)
	}
}

func protocolTestServer(t *testing.T, origins ...string) (*Server, *int) {
	t.Helper()
	calls := new(int)
	options := []ServerOption{WithEngine(snort.NewEngine()), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		*calls++
		if req.Header.Get("Accept-Encoding") != "identity" {
			t.Error("wire request missing inspected encoding policy")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Set-Cookie": {"a=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT", "b=2"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})})}
	if origins != nil {
		options = append(options, WithAllowedOrigins(origins...))
	}
	s, err := NewServer(options...)
	if err != nil {
		t.Fatal(err)
	}
	return s, calls
}

func TestDefaultDenyAndExactOrigins(t *testing.T) {
	s, err := NewServer(WithEngine(snort.NewEngine()))
	if err != nil {
		t.Fatal(err)
	}
	if got := diagnosticResult(t, s, map[string]any{"url": "https://api.example.com/v1"}); got["blocked"] != true {
		t.Fatal("default policy allowed egress", got)
	}
	s, calls := protocolTestServer(t, "https://api.example.com")
	for _, destination := range []string{"http://api.example.com/v1", "https://api.example.com.evil.test/v1", "https://evil.api.example.com/v1", "https://api.example.com:444/v1"} {
		result, _ := s.executeHTTPRequest(context.Background(), map[string]any{"url": destination})
		if !result.IsError {
			t.Error("origin policy bypass", destination)
		}
	}
	if *calls != 0 {
		t.Fatal("denied origins reached transport")
	}
	result, _ := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://API.example.com:443/v1"})
	if result.IsError || *calls != 1 {
		t.Fatalf("allowed origin failed: %+v calls=%d", result, *calls)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].Text), &output); err != nil {
		t.Fatal(err)
	}
	if values, ok := output["headers"].(map[string]any)["Set-Cookie"].([]any); !ok || len(values) != 2 {
		t.Error("Set-Cookie values were comma-collapsed")
	}
	if output["header_values"] == nil {
		t.Error("missing uncombined response headers")
	}
}

func TestInvalidRPCNeverDispatches(t *testing.T) {
	s, calls := protocolTestServer(t)
	for _, message := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"https://ok.test","url":"https://other.test"}}}`,
		`{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call"}`,
		`{"jsonrpc":"1.0","id":1,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"http_request","arguments":{"url":"https://ok.test"}}}`,
		`{"jsonrpc":"2.0","id":null,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":{},"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":9007199254740992,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"https://ok.test","body":"\ud800"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"https://ok.test"},"bypass":true}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"https://ok.test","allow_origin":true}}}`,
	} {
		var out bytes.Buffer
		if err := s.Serve(context.Background(), strings.NewReader(message+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"error"`) && !strings.Contains(out.String(), `"isError":true`) {
			t.Errorf("invalid request accepted: %s -> %s", message, out.String())
		}
	}
	if *calls != 0 {
		t.Fatalf("invalid RPC dispatched %d requests", *calls)
	}
}

func TestProtocolDispatchAndDiagnosticShareGate(t *testing.T) {
	for _, args := range []map[string]any{
		{"url": "https://ok.test/%c0%af"}, {"url": "https://ok.test/", "method": "get"},
		{"url": "https://ok.test/", "body": "hidden"}, {"url": "https://ok.test/", "headers": map[string]any{"Connection": "X-Auth"}},
		{"url": "https://ok.test/", "headers": map[string]any{"Sec-Fetch-Site": "same-origin"}},
		{"url": "https://ok.test/", "method": "POST", "body": `{"ok":true,"ok":false}`},
		{"url": "https://ok.test/", "method": "POST", "headers": map[string]any{"Content-Type": "application/octet-stream"}, "body": "opaque"},
	} {
		s, calls := protocolTestServer(t)
		diag := diagnosticResult(t, s, args)
		result, _ := s.executeHTTPRequest(context.Background(), args)
		if diag["blocked"] != true || !result.IsError || *calls != 0 {
			t.Errorf("gate diverged: %v %+v calls=%d", diag, result, *calls)
		}
	}
}

func TestCumulativeBudgets(t *testing.T) {
	s, calls := protocolTestServer(t)
	atomic.StoreUint64(&s.inspectionAttempts, MaxSessionInspections)
	if diag := diagnosticResult(t, s, map[string]any{"url": "https://ok.test/"}); diag["blocked"] != true {
		t.Fatal("inspection count budget bypass")
	}
	s, calls = protocolTestServer(t)
	atomic.StoreUint64(&s.inspectionBytes, MaxSessionBytes)
	result, _ := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://ok.test/"})
	if !result.IsError || *calls != 0 {
		t.Fatal("inspection byte budget bypass")
	}
	s, calls = protocolTestServer(t)
	atomic.StoreUint64(&s.responseBytes, MaxSessionBytes)
	result, _ = s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://ok.test/"})
	if !result.IsError || *calls != 0 {
		t.Fatal("response budget allowed further side effects")
	}
	s, _ = protocolTestServer(t)
	atomic.StoreUint64(&s.rpcMessages, 10000)
	if err := s.Serve(context.Background(), strings.NewReader("{}\n"), io.Discard); err == nil {
		t.Fatal("RPC count budget bypass")
	}
}

type measuredBody struct{ read int }

func (b *measuredBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}
func (*measuredBody) Close() error { return nil }

func TestResponseReadUsesRemainingSessionBudget(t *testing.T) {
	body := &measuredBody{}
	s, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	atomic.StoreUint64(&s.responseBytes, MaxSessionBytes-1)
	result, _ := s.executeHTTPRequest(context.Background(), map[string]any{"url": "https://ok.test/"})
	if !result.IsError || body.read != 2 {
		t.Fatalf("remaining byte + overflow probe: error=%v consumed=%d", result.IsError, body.read)
	}
}
