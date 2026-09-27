// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package snort

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Each rule must be independently reachable. A full-catalog blocked assertion
// alone could pass because a broader earlier rule hid a broken signature.
func TestCanonicalCatalogFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/rule_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			Name    string            `json:"name"`
			SID     int               `json:"sid"`
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
			Match   bool              `json:"match"`
			Profile string            `json:"profile"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.SchemaVersion != 1 {
		t.Fatalf("unsupported fixture schema %d", fixtures.SchemaVersion)
	}
	rules := map[int]*Rule{}
	profiles := map[int]string{}
	for _, pack := range []struct{ name, text string }{{"default", DefaultRulesSnort}, {"strict", StrictRulesSnort}} {
		parsed, err := ParseRules(strings.NewReader(pack.text))
		if err != nil {
			t.Fatalf("parse %s: %v", pack.name, err)
		}
		for _, r := range parsed {
			if rules[r.SID] != nil {
				t.Fatalf("duplicate catalog SID %d", r.SID)
			}
			rules[r.SID], profiles[r.SID] = r, pack.name
		}
	}
	if len(rules) < 200 {
		t.Fatalf("unexpectedly small catalog: %d", len(rules))
	}
	coverage := map[int]map[bool]bool{}
	names := map[string]bool{}
	for _, c := range fixtures.Cases {
		r, ok := rules[c.SID]
		if !ok {
			t.Fatalf("fixture references absent SID %d", c.SID)
		}
		if c.Profile != profiles[c.SID] {
			t.Fatalf("wrong fixture profile for SID %d", c.SID)
		}
		if names[c.Name] {
			t.Fatalf("duplicate fixture name %q", c.Name)
		}
		names[c.Name] = true
		if coverage[c.SID] == nil {
			coverage[c.SID] = map[bool]bool{}
		}
		coverage[c.SID][c.Match] = true
		t.Run(fmt.Sprintf("%d/%s", c.SID, c.Name), func(t *testing.T) {
			e := NewEngine()
			if err := e.AddRule(r); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(c.Method, c.URL, nil)
			if err != nil {
				t.Fatalf("invalid fixture request: %v", err)
			}
			for k, v := range c.Headers {
				req.Header.Set(k, v)
			}
			got := e.InspectHTTPRequest(req, []byte(c.Body))
			if got.Matched != c.Match {
				t.Fatalf("matched=%v want=%v: %+v", got.Matched, c.Match, got)
			}
			wantBlocked := c.Match && r.Action != ActionAlert
			if got.Blocked != wantBlocked {
				t.Fatalf("blocked=%v want=%v: %+v", got.Blocked, wantBlocked, got)
			}
			if c.Match && (got.MatchedRule == nil || got.MatchedRule.SID != c.SID) {
				t.Fatalf("fixture did not reach SID %d: %+v", c.SID, got)
			}
		})
	}
	for sid := range rules {
		if !coverage[sid][true] || !coverage[sid][false] {
			t.Errorf("SID %d requires positive and benign near-miss fixtures", sid)
		}
	}
}

func TestCatalogOrdinaryAuthenticatedRequests(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		t.Run(profile, func(t *testing.T) {
			e, err := NewProfileEngine(profile)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{"ghp_" + strings.Repeat("A", 36), "github_pat_" + strings.Repeat("A", 60), "sk_live_" + strings.Repeat("A", 24), "xoxb-123456789012-abcdefghijklmnop"} {
				req, err := http.NewRequest("POST", "https://api.example/v1/messages", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				got := e.InspectHTTPRequest(req, []byte(`{"message":"Please summarize the quarterly sales report."}`))
				if got.Blocked || (got.Matched && (got.MatchedRule.SID != 9114035 || got.Action != ActionAlert)) {
					t.Fatalf("ordinary authenticated request matched: %+v", got)
				}
			}
		})
	}
}
