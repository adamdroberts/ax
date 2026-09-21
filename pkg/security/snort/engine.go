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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Engine evaluates Snort rules against HTTP request targets.
type Engine struct {
	mu    sync.RWMutex
	rules []*Rule
}

// NewEngine creates an empty Snort inspection engine.
func NewEngine() *Engine {
	return &Engine{
		rules: make([]*Rule, 0),
	}
}

// AddRule registers a compiled Snort rule.
func (e *Engine) AddRule(r *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// RuleCount returns the total number of rules currently loaded.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// LoadRulesFromReader parses and registers rules from an io.Reader.
func (e *Engine) LoadRulesFromReader(r io.Reader) (int, error) {
	parsed, err := ParseRules(r)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, parsed...)
	return len(parsed), nil
}

// LoadRulesFromFile reads a Snort rules file from disk and loads the rules.
func (e *Engine) LoadRulesFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening rules file %s: %w", path, err)
	}
	defer f.Close()
	return e.LoadRulesFromReader(f)
}

// InspectHTTPRequest converts a standard Go http.Request and its body into an inspection target and evaluates it.
func (e *Engine) InspectHTTPRequest(req *http.Request, body []byte) MatchResult {
	target := BuildInspectionTarget(req, string(body))
	return e.Inspect(target)
}

// Inspect evaluates all loaded rules against the inspection target.
func (e *Engine) Inspect(target *HTTPInspectionTarget) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var firstAlert *MatchResult

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesRule(rule, target) {
			isBlocking := rule.Action == ActionDrop || rule.Action == ActionBlock || rule.Action == ActionReject
			res := MatchResult{
				Matched:     true,
				Action:      rule.Action,
				Blocked:     isBlocking,
				MatchedRule: rule,
				Reason:      fmt.Sprintf("[SID %d] %s: %s", rule.SID, rule.ClassType, rule.Message),
			}

			// Blocking actions take precedence immediately
			if isBlocking {
				return res
			}
			if firstAlert == nil {
				firstAlert = &res
			}
		}
	}

	if firstAlert != nil {
		return *firstAlert
	}

	return MatchResult{
		Matched: false,
		Blocked: false,
	}
}

// matchesRule checks if all content and PCRE conditions in a rule are satisfied.
func (e *Engine) matchesRule(rule *Rule, target *HTTPInspectionTarget) bool {
	// 1. Evaluate all Contents
	for _, co := range rule.Contents {
		buf := getTargetBuffer(target, co.Target)
		matched := matchContent(buf, co)
		if !matched {
			return false
		}
	}

	// 2. Evaluate all PCREs
	for _, po := range rule.PCREs {
		buf := getTargetBuffer(target, po.Target)
		matched := matchPCRE(buf, po)
		if !matched {
			return false
		}
	}

	return true
}

func matchContent(buf string, co ContentOption) bool {
	searchIn := buf
	pattern := co.Pattern

	if co.NoCase {
		searchIn = strings.ToLower(searchIn)
		pattern = strings.ToLower(pattern)
	}

	if co.Offset > 0 {
		if co.Offset >= len(searchIn) {
			return co.Negated
		}
		searchIn = searchIn[co.Offset:]
	}

	if co.Depth > 0 && co.Depth < len(searchIn) {
		searchIn = searchIn[:co.Depth]
	}

	contains := strings.Contains(searchIn, pattern)
	if co.Negated {
		return !contains
	}
	return contains
}

func matchPCRE(buf string, po PCREOption) bool {
	if po.Regex == nil {
		return false
	}
	matched := po.Regex.MatchString(buf)
	if po.Negated {
		return !matched
	}
	return matched
}

func getTargetBuffer(target *HTTPInspectionTarget, tm TargetModifier) string {
	switch tm {
	case TargetHTTPURI:
		// Check full URL, raw and URL-decoded full URI
		decodedURI, _ := url.QueryUnescape(target.FullURI)
		decodedURL, _ := url.QueryUnescape(target.URL)
		return target.URL + " " + decodedURL + " " + target.FullURI + " " + decodedURI
	case TargetHTTPHeader:
		return target.HeadersRaw
	case TargetHTTPBody:
		return target.Body
	case TargetHTTPMethod:
		return target.Method
	case TargetAll:
		fallthrough
	default:
		// Search across URI, decoded URI, headers, and body
		decoded, err := url.QueryUnescape(target.FullURI)
		if err == nil && decoded != target.FullURI {
			return target.Method + " " + target.FullURI + " " + decoded + "\n" + target.HeadersRaw + "\n" + target.Body
		}
		return target.Method + " " + target.FullURI + "\n" + target.HeadersRaw + "\n" + target.Body
	}
}

// BuildInspectionTarget extracts and normalizes the request components for inspection.
func BuildInspectionTarget(req *http.Request, body string) *HTTPInspectionTarget {
	fullURI := req.URL.RequestURI()
	if fullURI == "" {
		fullURI = req.URL.Path
	}

	var headersRaw strings.Builder
	for k, vList := range req.Header {
		for _, v := range vList {
			headersRaw.WriteString(k)
			headersRaw.WriteString(": ")
			headersRaw.WriteString(v)
			headersRaw.WriteString("\n")
		}
	}

	return &HTTPInspectionTarget{
		Method:     req.Method,
		URL:        req.URL.String(),
		Path:       req.URL.Path,
		Query:      req.URL.RawQuery,
		FullURI:    fullURI,
		Headers:    req.Header,
		HeadersRaw: headersRaw.String(),
		Body:       body,
		RemoteHost: req.URL.Hostname(),
		RemotePort: req.URL.Port(),
	}
}
