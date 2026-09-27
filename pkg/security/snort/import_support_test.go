package snort

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func importRuleEngine(t *testing.T, matcher string) *Engine {
	t.Helper()
	e := NewEngine()
	if _, err := e.LoadRulesFromReader(strings.NewReader(`drop http any any -> any any (` + matcher + ` sid:1;)`)); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestImportedRawBufferSemantics(t *testing.T) {
	req, err := http.NewRequest("POST", "https://origin.example/%65vil?value=%41", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, matcher string
		match         bool
	}{
		{"raw URI keeps escaping", `pcre:"/^\/%65vil\?value=%41$/"; http_raw_uri;`, true},
		{"raw URI excludes authority", `content:"origin.example"; http_raw_uri;`, false},
		{"raw URI excludes decoded views", `content:"evil"; http_raw_uri;`, false},
		{"normalized URI retains decoded views", `content:"evil"; http_uri;`, true},
		{"raw body keeps escaping", `pcre:"/^%65vil$/"; http_raw_body;`, true},
		{"raw body excludes decoded views", `content:"evil"; http_raw_body;`, false},
		{"normalized body retains decoded views", `content:"evil"; http_client_body;`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := importRuleEngine(t, tc.matcher).InspectHTTPRequest(req, []byte("%65vil"))
			if got.Matched != tc.match || got.Blocked != tc.match {
				t.Fatalf("match=%v want=%v: %+v", got.Matched, tc.match, got)
			}
		})
	}
}

func TestImportedHeaderFieldValuesAndHost(t *testing.T) {
	req, err := http.NewRequest("POST", "https://origin.example:8443/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "destination.example:9443"
	req.Header["uSeR-aGeNt"] = []string{"safe-client", "%65vil-client"}
	req.Header.Set("Host", "unrelated.example")
	req.Header.Set("X-Other", "secret")
	for _, tc := range []struct {
		name, matcher string
		match         bool
	}{
		{"mixed case and decoded value", `pcre:"/^evil-client$/"; http_header:field USER-AGENT;`, true},
		{"only selected field", `content:"secret"; http_header:field user-agent;`, false},
		{"no header prefix", `content:"uSeR-aGeNt:"; http_header:field user-agent;`, false},
		{"host override", `pcre:"/^destination\.example:9443$/"; http_header:field host;`, true},
		{"host excludes URL fallback when overridden", `content:"origin.example"; http_header:field host;`, false},
		{"host excludes map shadow", `content:"unrelated.example"; http_header:field host;`, false},
		{"missing field positive", `content:"secret"; http_header:field x-missing;`, false},
		{"missing field negated content", `content:!"secret"; http_header:field x-missing;`, false},
		{"missing field negated regex", `pcre:!"/secret/"; http_header:field x-missing;`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := importRuleEngine(t, tc.matcher).InspectHTTPRequest(req, nil)
			if got.Matched != tc.match || got.Blocked != tc.match {
				t.Fatalf("match=%v want=%v: %+v", got.Matched, tc.match, got)
			}
		})
	}
	req.Host = ""
	engine := importRuleEngine(t, `pcre:"/^origin\.example:8443$/"; http_header:field host;`)
	if got := engine.InspectHTTPRequest(req, nil); !got.Matched {
		t.Fatalf("URL authority fallback failed: %+v", got)
	}
	// Manually constructed targets use the same URL authority fallback.
	target := BuildInspectionTarget(req, "")
	target.Host = ""
	if got := engine.Inspect(target); !got.Matched {
		t.Fatalf("manual target URL authority fallback failed: %+v", got)
	}
}

func TestImportedFieldModifierValidation(t *testing.T) {
	for _, modifier := range []string{
		"http_header:field", "http_header:host", "http_header:field x bad",
		"http_header:field bad:name", "http_header:field x,request",
		"http_uri:field host", "http_raw_uri:field host", "http_raw_body:field host",
		"http_raw_header", "http_raw_header:field host", "file_data", "pkt_data",
		"http_header:field host; http_header", "http_header:field host; http_raw_uri",
	} {
		t.Run(modifier, func(t *testing.T) {
			raw := `drop http any any -> any any (content:"x"; ` + modifier + `; sid:1;)`
			if _, err := ParseRule(raw); err == nil {
				t.Fatal("invalid or unsupported modifier accepted")
			}
		})
	}
	rule, err := ParseRule(`drop http any any -> any any (content:"x"; http_header:field X-Test; sid:1;)`)
	if err != nil {
		t.Fatal(err)
	}
	if got := rule.Contents[0].Target; got != TargetModifier("http_header:field x-test") {
		t.Fatalf("field modifier was not canonicalized: %q", got)
	}
}

func strictTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine()
	for sid := 1; sid <= 4; sid++ {
		action := "alert"
		if sid == 4 {
			action = "drop"
		}
		raw := fmt.Sprintf(`%s http any any -> any any (content:"payload%d"; http_client_body; sid:%d;)`, action, sid, sid)
		if _, err := e.LoadRulesFromReader(strings.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestStrictActionsAreAtomicAndOnlyPromoteAlerts(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{"1":"drop"`, `{"1":"drop"} {}`, `{"1":"drop"} trailing`,
		`{"1":"drop","1":"block"}`, `{"01":"drop"}`, `{"0":"drop"}`, `{"-1":"drop"}`,
		`{"2147483648":"drop"}`, `{"+1":"drop"}`, `{"a":"drop"}`,
		`{"1":"drop","2":"alert"}`, `{"1":"drop","2":"pass"}`, `{"1":"drop","2":null}`,
		`{"1":"drop","2":true}`, `{"1":"drop","2":5}`, `{"1":"drop","2":{}}`,
		`{"1":"drop","9":"drop"}`, `{"1":"drop","4":"drop"}`,
	} {
		t.Run(input, func(t *testing.T) {
			e := strictTestEngine(t)
			before := e.rules[0]
			if err := e.applyStrictActions(strings.NewReader(input)); err == nil {
				t.Fatal("invalid strict override accepted")
			}
			if e.RuleCount() != 4 || e.rules[0] != before || e.rules[0].Action != ActionAlert {
				t.Fatal("invalid overrides changed the engine")
			}
		})
	}
	e := strictTestEngine(t)
	before := e.rules[0]
	if err := e.applyStrictActions(strings.NewReader(`{"1":"drop","2":"block","3":"reject"}`)); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() != 4 || before.Action != ActionAlert {
		t.Fatal("override cloned a signature or mutated a previously returned rule")
	}
	req, _ := http.NewRequest("POST", "https://example.test", nil)
	for sid, action := range []Action{ActionDrop, ActionBlock, ActionReject} {
		got := e.InspectHTTPRequest(req, []byte(fmt.Sprintf("payload%d", sid+1)))
		if !got.Blocked || got.Action != action {
			t.Fatalf("SID %d promotion failed: %+v", sid+1, got)
		}
		parsed, err := ParseRule(got.MatchedRule.Raw)
		if err != nil || parsed.Action != action {
			t.Fatalf("effective serialized action lost: %v, %+v", err, parsed)
		}
	}
}

func TestStrictProfileUsesOverridesWithoutDuplicateRules(t *testing.T) {
	baseline, err := NewProfileEngine("default")
	if err != nil {
		t.Fatal(err)
	}
	strict, err := NewProfileEngine("strict")
	if err != nil {
		t.Fatal(err)
	}
	extra, err := ParseRules(strings.NewReader(StrictRulesSnort))
	if err != nil {
		t.Fatal(err)
	}
	if strict.RuleCount() != baseline.RuleCount()+len(extra) {
		t.Fatal("action overrides duplicated a rule")
	}
	var overrides map[string]Action
	if err := json.Unmarshal([]byte(StrictActionsJSON), &overrides); err != nil {
		t.Fatal(err)
	}
	for _, rule := range strict.rules {
		if expected, ok := overrides[fmt.Sprint(rule.SID)]; ok && rule.Action != expected {
			t.Errorf("SID %d has %s instead of %s", rule.SID, rule.Action, expected)
		}
	}
	for _, rule := range baseline.rules {
		if _, promoted := overrides[fmt.Sprint(rule.SID)]; promoted && rule.Action != ActionAlert {
			t.Errorf("SID %d was promoted in the default profile", rule.SID)
		}
	}
}
