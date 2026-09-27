package snort

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestNocaseViewsPreserveByteWindowsAndOtherMatchers(t *testing.T) {
	cases := []struct {
		name, rule, body string
		blocked          bool
	}{
		{"UTF8 byte offset", `content:"EVIL"; nocase; http_raw_body; offset:2; depth:4;`, "éEvIl", true},
		{"offset is not character based", `content:"EVIL"; nocase; http_raw_body; offset:2; depth:4;`, "xéEvIl", false},
		{"depth still enforced", `content:"EVIL"; nocase; http_raw_body; offset:2; depth:3;`, "éEvIl", false},
		{"negated window", `content:!"EVIL"; nocase; http_raw_body; offset:2; depth:4;`, "éEvIl", false},
		{"negated clear window", `content:!"EVIL"; nocase; http_raw_body; offset:2; depth:4;`, "égood", true},
		{"case sensitive regex gets original", `content:"EVIL"; nocase; http_client_body; pcre:"/^EVIL$/"; http_client_body;`, "EvIl", false},
		{"case sensitive regex still matches", `content:"EVIL"; nocase; http_client_body; pcre:"/^EVIL$/"; http_client_body;`, "EVIL", true},
		{"raw body stays encoded", `content:"EVIL"; nocase; http_raw_body;`, "%45VIL", false},
		{"decoded body still matches", `content:"EVIL"; nocase; http_client_body;`, "%45VIL", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewEngine()
			_, err := engine.LoadRulesFromReader(strings.NewReader(`drop tcp any any -> any any (` + tc.rule + ` sid:1;)`))
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest("POST", "https://example.test/check", nil)
			if got := engine.InspectHTTPRequest(req, []byte(tc.body)); got.Blocked != tc.blocked {
				t.Fatalf("blocked=%v, want %v: %+v", got.Blocked, tc.blocked, got)
			}
		})
	}
}

func TestNocaseAllocationsDoNotScaleWithRuleCount(t *testing.T) {
	// An uppercase body previously allocated another full lowercase body for
	// every nocase rule. Make the amplification observable without timing-based
	// assertions or a machine-dependent resident-memory threshold.
	request, _ := http.NewRequest("POST", "https://example.test/check", nil)
	body := []byte(strings.Repeat("ORDINARYVALUE ", 4096))
	allocations := func(count int) float64 {
		engine := NewEngine()
		var rules strings.Builder
		for i := 1; i <= count; i++ {
			fmt.Fprintf(&rules, "alert tcp any any -> any any (content:\"absent-token-%d\"; nocase; http_client_body; sid:%d;)\n", i, i)
		}
		if _, err := engine.LoadRulesFromReader(strings.NewReader(rules.String())); err != nil {
			t.Fatal(err)
		}
		return testing.AllocsPerRun(3, func() {
			if got := engine.InspectHTTPRequest(request, body); got.Blocked || got.Matched {
				t.Fatalf("benign request unexpectedly matched: %+v", got)
			}
		})
	}
	small, large := allocations(8), allocations(256)
	if large > small+8 {
		t.Fatalf("allocation count scales with signatures: 8 rules=%g, 256 rules=%g", small, large)
	}
}

func TestConcurrentNocaseInspectionResultsStayRequestLocal(t *testing.T) {
	engine := NewEngine()
	if _, err := engine.LoadRulesFromReader(strings.NewReader(`drop tcp any any -> any any (content:"evil"; nocase; http_client_body; sid:1;)`)); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(blocked bool) {
			defer workers.Done()
			body := "BENIGN"
			if blocked {
				body = "EVIL"
			}
			request, _ := http.NewRequest("POST", "https://example.test/check", nil)
			for j := 0; j < 8; j++ {
				if got := engine.InspectHTTPRequest(request, []byte(body)); got.Blocked != blocked {
					t.Errorf("concurrent request changed result: %+v", got)
					return
				}
			}
		}(i%2 == 0)
	}
	workers.Wait()
}

func TestNormalizationRequiresFixedPointWithinDepthLimit(t *testing.T) {
	for _, value := range []string{"%25252565vil", "%2525256frdinary", "&amp;amp;amp;amp;lt;"} {
		t.Run(value, func(t *testing.T) {
			if _, err := normalizedViews(value, MaxBodyBytes); err == nil {
				t.Fatal("deeper encoding silently escaped inspection")
			}
		})
	}
	for _, value := range []string{"%252565vil", "%25256frdinary", "&amp;amp;lt;", "100% ordinary", "ordinary"} {
		t.Run(value, func(t *testing.T) {
			if _, err := normalizedViews(value, MaxBodyBytes); err != nil {
				t.Fatalf("bounded fixed point rejected: %v", err)
			}
		})
	}
	engine := NewEngine()
	request, _ := http.NewRequest("POST", "https://example.test/check", nil)
	result := engine.InspectHTTPRequest(request, []byte("%2525256frdinary"))
	if !result.Blocked || result.MatchedRule != nil {
		t.Fatalf("normalization rejection must fail closed independently of signatures: %+v", result)
	}
}
