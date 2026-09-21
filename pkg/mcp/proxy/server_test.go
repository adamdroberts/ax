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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	srv, err := NewServer()
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
		mockUpstream.URL,
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
		mockUpstream.URL,
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
