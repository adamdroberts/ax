// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/ax/pkg/security/snort"
)

func TestMCPServerLifecycle(t *testing.T) {
	ctx := context.Background()

	// Mock upstream HTTP server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Header") == "TestValue" {
			w.Header().Set("X-Upstream-Response", "Validated")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","data":"authorized_response"}`))
	}))
	defer mockUpstream.Close()

	// Keep the policy-visible destination public while routing the test transport
	// to loopback; the baseline correctly blocks real loopback destination URLs.
	upstreamURL, _ := url.Parse(mockUpstream.URL)
	testClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, upstreamURL.Host)
	}}}
	defer testClient.CloseIdleConnections()
	const policyURL = "http://service.example.test"
	srv, err := NewServer(WithHTTPClient(testClient))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Test Initialize
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}` + "\n"
	in := strings.NewReader(initReq)
	var out bytes.Buffer

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var initResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &initResp); err != nil {
		t.Fatalf("unmarshaling initialize response: %v\nOutput was: %s", err, out.String())
	}
	if initResp.Error != nil {
		t.Fatalf("unexpected initialize error: %+v", initResp.Error)
	}

	// 2. Test Tools/List
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	in = strings.NewReader(listReq)
	out.Reset()

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var listResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshaling tools/list response: %v", err)
	}
	resMap, ok := listResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got: %+v", listResp.Result)
	}
	tools, ok := resMap["tools"].([]any)
	if !ok || len(tools) < 3 {
		t.Fatalf("expected at least 3 tools, got: %v", tools)
	}

	// 3. Test Blocked Exploit: Command Injection in HTTP Body
	exploitReq := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"%s/api","method":"POST","body":"param=1; cat /etc/passwd"}}}`+"\n",
		policyURL,
	)
	in = strings.NewReader(exploitReq)
	out.Reset()

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var exploitResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &exploitResp); err != nil {
		t.Fatalf("unmarshaling exploit response: %v", err)
	}
	callResMap, ok := exploitResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected tool call result, got: %+v", exploitResp)
	}
	if callResMap["isError"] != true {
		t.Errorf("expected isError=true for blocked exploit, got: %v", callResMap["isError"])
	}
	contentArr := callResMap["content"].([]any)
	firstContent := contentArr[0].(map[string]any)
	text := firstContent["text"].(string)
	if !strings.Contains(text, "SECURITY VIOLATION") || !strings.Contains(text, "1000006") {
		t.Errorf("expected security violation for SID 1000006, got text: %s", text)
	}

	// 4. Test Legitimate HTTP Request to Upstream
	legitReq := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"%s/safe","method":"GET","headers":{"X-Custom-Header":"TestValue"}}}}`+"\n",
		policyURL,
	)
	in = strings.NewReader(legitReq)
	out.Reset()

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var legitResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &legitResp); err != nil {
		t.Fatalf("unmarshaling legit response: %v", err)
	}
	legitMap := legitResp.Result.(map[string]any)
	if legitMap["isError"] == true {
		t.Fatalf("expected successful call, got error: %+v", legitMap)
	}
	legitContent := legitMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(legitContent, "authorized_response") || !strings.Contains(legitContent, "200") {
		t.Errorf("expected response to contain authorized_response, got: %s", legitContent)
	}

	// 5. Test Diagnostic Tool check_security_payload
	diagReq := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"check_security_payload","arguments":{"url":"http://169.254.169.254/latest/meta-data"}}}` + "\n"
	in = strings.NewReader(diagReq)
	out.Reset()

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var diagResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &diagResp); err != nil {
		t.Fatalf("unmarshaling diag response: %v", err)
	}
	diagText := diagResp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(diagText, `"blocked": true`) || !strings.Contains(diagText, "1000030") {
		t.Errorf("expected diagnostic check to report blocked SID 1000030, got: %s", diagText)
	}

	// 6. Test get_security_stats
	statsReq := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_security_stats","arguments":{}}}` + "\n"
	in = strings.NewReader(statsReq)
	out.Reset()

	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve error: %v", err)
	}

	var statsResp JSONRPCResponse
	if err := json.Unmarshal(out.Bytes(), &statsResp); err != nil {
		t.Fatalf("unmarshaling stats response: %v", err)
	}
	statsText := statsResp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(statsText, `"total_blocked": 1`) || !strings.Contains(statsText, `"total_passed": 1`) {
		t.Errorf("expected stats to record 1 blocked and 1 passed, got: %s", statsText)
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func diagnosticResult(t *testing.T, server *Server, args map[string]any) map[string]any {
	t.Helper()
	result, rpcErr := server.executeCheckPayload(args)
	if rpcErr != nil || result == nil || len(result.Content) != 1 {
		t.Fatalf("invalid diagnostic result: %+v / %+v", result, rpcErr)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].Text), &decoded); err != nil {
		t.Fatalf("decode diagnostic: %v", err)
	}
	return decoded
}

func TestRequestValidationBlocksBeforeTransportAndMatchesDiagnostic(t *testing.T) {
	manyHeaders := map[string]any{}
	for i := 0; i <= snort.MaxHeaders; i++ {
		manyHeaders[fmt.Sprintf("X-Header-%d", i)] = "ok"
	}
	tests := []struct {
		name string
		args map[string]any
	}{
		{"missing URL", map[string]any{}},
		{"relative URL", map[string]any{"url": "/relative"}},
		{"empty hostname", map[string]any{"url": "http://:80/path"}},
		{"file URL", map[string]any{"url": "file:///etc/passwd"}},
		{"FTP URL", map[string]any{"url": "ftp://example.com/file"}},
		{"userinfo", map[string]any{"url": "https://user:secret@example.com/path"}},
		{"long URL", map[string]any{"url": "https://example.com/" + strings.Repeat("x", snort.MaxURLBytes)}},
		{"large body", map[string]any{"body": strings.Repeat("x", snort.MaxBodyBytes+1)}},
		{"body type", map[string]any{"body": map[string]any{"command": "hidden"}}},
		{"method type", map[string]any{"method": true}},
		{"method newline", map[string]any{"method": "GET\r\nX-Injected: yes"}},
		{"headers type", map[string]any{"headers": []string{"X-Foo: bar"}}},
		{"header value type", map[string]any{"headers": map[string]any{"X-Foo": 3}}},
		{"header name whitespace", map[string]any{"headers": map[string]any{"X-Foo ": "bar"}}},
		{"header newline", map[string]any{"headers": map[string]any{"X-Foo": "bar\r\nX-Injected: yes"}}},
		{"header NUL", map[string]any{"headers": map[string]any{"X-Foo": "bar\x00"}}},
		{"case duplicate headers", map[string]any{"headers": map[string]any{"X-Foo": "one", "x-foo": "two"}}},
		{"Host override", map[string]any{"headers": map[string]any{"Host": "other.example"}}},
		{"Content-Length override", map[string]any{"headers": map[string]any{"Content-Length": "99"}}},
		{"Transfer-Encoding override", map[string]any{"headers": map[string]any{"Transfer-Encoding": "chunked"}}},
		{"Proxy-Authorization override", map[string]any{"headers": map[string]any{"Proxy-Authorization": "Basic secret"}}},
		{"Proxy-Connection override", map[string]any{"headers": map[string]any{"Proxy-Connection": "keep-alive"}}},
		{"compressed body", map[string]any{"headers": map[string]any{"Content-Encoding": "gzip"}}},
		{"multiple encodings", map[string]any{"headers": map[string]any{"Content-Encoding": "identity, gzip"}}},
		{"too many headers", map[string]any{"headers": manyHeaders}},
		{"large headers", map[string]any{"headers": map[string]any{"X-Foo": strings.Repeat("x", snort.MaxHeaderBytes)}}},
		{"timeout overflow", map[string]any{"timeout_seconds": float64(1e20)}},
		{"timeout fraction", map[string]any{"timeout_seconds": float64(1.5)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, exists := tc.args["url"]; !exists && tc.name != "missing URL" {
				tc.args["url"] = "https://example.com/safe"
			}
			calls := 0
			client := &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("request should have been blocked")
			})}
			server, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			diagnostic := diagnosticResult(t, server, tc.args)
			if diagnostic["blocked"] != true || diagnostic["matched"] != false || diagnostic["reason"] == "" {
				t.Fatalf("expected explicit validation block, got %+v", diagnostic)
			}
			result, rpcErr := server.executeHTTPRequest(context.Background(), tc.args)
			if rpcErr != nil || !result.IsError || !strings.Contains(result.Content[0].Text, diagnostic["reason"].(string)) {
				t.Fatalf("dispatch and diagnostics disagree: %+v / %+v / %+v", result, rpcErr, diagnostic)
			}
			if calls != 0 || server.stats.TotalBlocked != 1 || server.stats.TotalPassed != 0 {
				t.Fatalf("blocked request reached transport or wrong stats: calls=%d stats=%+v", calls, server.stats)
			}
		})
	}
}

func TestRuleBlockNeverDispatchesOrLogsSecrets(t *testing.T) {
	engine := snort.NewEngine()
	if _, err := engine.LoadRulesFromReader(strings.NewReader(`drop http any any -> any any (msg:"Blocked command"; content:"cat /etc/passwd"; http_client_body; sid:990001; rev:1;)`)); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)
	calls := 0
	server, err := NewServer(WithEngine(engine), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected dispatch")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{
		"url": "https://example.com/api?api_key=secret-query", "method": "POST", "body": "; cat /etc/passwd body-secret",
		"headers": map[string]any{"Authorization": "Bearer secret-header"},
	}
	diagnostic := diagnosticResult(t, server, args)
	result, _ := server.executeHTTPRequest(context.Background(), args)
	if !result.IsError || diagnostic["blocked"] != true || calls != 0 {
		t.Fatalf("expected rule to block both paths without dispatch: result=%+v diagnostic=%+v calls=%d", result, diagnostic, calls)
	}
	for _, secret := range []string{"example.com", "secret-query", "body-secret", "secret-header", "cat /etc/passwd"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("security log leaked request data %q", secret)
		}
	}
}

func TestRedirectsAreReturnedWithoutFollowingAndClientIsPreserved(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	originCookies := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCookies <- r.Header.Get("Cookie")
		http.Redirect(w, r, target.URL+"/uninspected", http.StatusFound)
	}))
	defer origin.Close()
	jar, _ := cookiejar.New(nil)
	originURL, _ := url.Parse(origin.URL)
	jar.SetCookies(originURL, []*http.Cookie{{Name: "uninspected", Value: "secret"}})
	redirectCallbacks := 0
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		redirectCallbacks++
		return nil
	}}
	server, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	result, rpcErr := server.executeHTTPRequest(context.Background(), map[string]any{"url": origin.URL})
	if rpcErr != nil || result.IsError || !strings.Contains(result.Content[0].Text, `"status_code": 302`) {
		t.Fatalf("expected original 302 response, got %+v / %+v", result, rpcErr)
	}
	originCookie := <-originCookies
	if targetCalls.Load() != 0 || redirectCallbacks != 0 || originCookie != "" {
		t.Fatalf("unexpected uninspected traffic: target=%d redirects=%d cookie=%q", targetCalls.Load(), redirectCallbacks, originCookie)
	}
	if client.Jar != jar || client.CheckRedirect == nil || server.httpClient == client {
		t.Fatal("caller HTTP client was mutated")
	}
}

func TestResponseSizeLimitRejectsOverflowWithoutTruncation(t *testing.T) {
	for _, size := range []int{MaxResponseBodyBytes, MaxResponseBodyBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			server, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size)))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			result, _ := server.executeHTTPRequest(context.Background(), map[string]any{"url": "https://example.com/safe"})
			if size > MaxResponseBodyBytes {
				if !result.IsError || !strings.Contains(result.Content[0].Text, "exceeds the 10 MiB limit") || strings.Contains(result.Content[0].Text, "xxx") {
					t.Fatalf("expected explicit overflow without body content, got %+v", result)
				}
			} else if result.IsError {
				t.Fatalf("response at limit was rejected: %+v", result)
			}
		})
	}
}

func TestTransportErrorsDoNotEchoCredentials(t *testing.T) {
	server, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed with secret-token")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	result, _ := server.executeHTTPRequest(context.Background(), map[string]any{"url": "https://example.com/?token=secret-token"})
	if !result.IsError || strings.Contains(result.Content[0].Text, "secret-token") || strings.Contains(result.Content[0].Text, "example.com") {
		t.Fatalf("transport error leaked sensitive detail: %+v", result)
	}
}

func TestNilHTTPClientRejected(t *testing.T) {
	if _, err := NewServer(WithEngine(snort.NewEngine()), WithHTTPClient(nil)); err == nil {
		t.Fatal("expected nil client to be rejected")
	}
}

func TestAdvisoryAllowsDispatchAndLogsOnlyPolicyIdentifiers(t *testing.T) {
	engine := snort.NewEngine()
	if _, err := engine.LoadRulesFromReader(strings.NewReader(`alert http any any -> any any (msg:"Advisory"; content:"advisory-marker"; http_client_body; sid:990004; rev:1;)`)); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)
	calls := 0
	server, err := NewServer(WithEngine(engine), WithHTTPClient(&http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{
		"url": "https://example.com/api?api_key=secret-query", "method": "POST", "body": "advisory-marker body-secret",
		"headers": map[string]any{"Authorization": "Bearer secret-header"},
	}
	diagnostic := diagnosticResult(t, server, args)
	result, _ := server.executeHTTPRequest(context.Background(), args)
	if result.IsError || calls != 1 || diagnostic["blocked"] != false || diagnostic["matched"] != true {
		t.Fatalf("advisory must permit dispatch and report a match: result=%+v diagnostic=%+v calls=%d", result, diagnostic, calls)
	}
	if !strings.Contains(logs.String(), "sid=990004") || !strings.Contains(logs.String(), "action=alert") {
		t.Fatalf("expected advisory policy identifiers in log, got %s", logs.String())
	}
	for _, secret := range []string{"example.com", "secret-query", "body-secret", "secret-header", "advisory-marker"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("advisory log leaked request data %q", secret)
		}
	}
}
