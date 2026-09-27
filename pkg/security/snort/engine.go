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
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	MaxBodyBytes   = 1 << 20
	MaxURLBytes    = 16 << 10
	MaxHeaderBytes = 64 << 10
	MaxHeaders     = 128
	maxViews       = 16
)

// Engine inspects outbound HTTP requests using the documented AX rule subset.
// It does not mediate arbitrary sockets, DNS, local tools, or response bodies.
type Engine struct {
	mu    sync.RWMutex
	rules []*Rule
}

func NewEngine() *Engine { return &Engine{} }

// AddRule validates a serialized rule before registration. Callers cannot install
// malformed or duplicate rules through the programmatic interface either.
func (e *Engine) AddRule(r *Rule) error {
	if r == nil {
		return fmt.Errorf("nil rule")
	}
	parsed, err := ParseRules(strings.NewReader(r.Raw))
	if err != nil {
		return err
	}
	if len(parsed) != 1 {
		return fmt.Errorf("AddRule requires exactly one serialized rule")
	}
	parsed[0].Enabled = r.Enabled
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, current := range e.rules {
		if current.SID == parsed[0].SID {
			return fmt.Errorf("duplicate SID %d", current.SID)
		}
	}
	e.rules = append(e.rules, parsed[0])
	return nil
}
func (e *Engine) RuleCount() int { e.mu.RLock(); defer e.mu.RUnlock(); return len(e.rules) }

// LoadRulesFromReader is atomic: invalid/duplicate SIDs leave the engine unchanged.
func (e *Engine) LoadRulesFromReader(r io.Reader) (int, error) {
	parsed, err := ParseRules(r)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[int]bool{}
	for _, r := range e.rules {
		seen[r.SID] = true
	}
	for _, r := range parsed {
		if seen[r.SID] {
			return 0, fmt.Errorf("duplicate SID %d", r.SID)
		}
		seen[r.SID] = true
	}
	e.rules = append(e.rules, parsed...)
	return len(parsed), nil
}
func (e *Engine) LoadRulesFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening rules file: %w", err)
	}
	defer f.Close()
	return e.LoadRulesFromReader(f)
}
func denied(reason string) MatchResult {
	return MatchResult{Blocked: true, Action: ActionReject, Reason: reason}
}
func (e *Engine) InspectHTTPRequest(req *http.Request, body []byte) MatchResult {
	if req == nil || req.URL == nil {
		return denied("invalid HTTP request")
	}
	return e.Inspect(BuildInspectionTarget(req, string(body)))
}

// Inspect builds bounded normalization views once. A blocking rule always wins
// over alerts. A policy rejection has no MatchedRule (it is not a signature).
func (e *Engine) Inspect(target *HTTPInspectionTarget) MatchResult {
	if err := validateTarget(target); err != nil {
		return denied(err.Error())
	}
	buffers, err := buildBuffers(target)
	if err != nil {
		return denied(err.Error())
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	var firstAlert *MatchResult
	for _, rule := range e.rules {
		if !rule.Enabled || !matchesBuffers(rule, buffers) {
			continue
		}
		blocked := rule.Action == ActionDrop || rule.Action == ActionBlock || rule.Action == ActionReject
		res := MatchResult{Matched: true, Action: rule.Action, Blocked: blocked, MatchedRule: rule, Reason: fmt.Sprintf("[SID %d] %s: %s", rule.SID, rule.ClassType, rule.Message)}
		if blocked {
			return res
		}
		if firstAlert == nil {
			firstAlert = &res
		}
	}
	if firstAlert != nil {
		return *firstAlert
	}
	return MatchResult{}
}

func validateTarget(t *HTTPInspectionTarget) error {
	if t == nil {
		return fmt.Errorf("invalid inspection target")
	}
	if len(t.Body) > MaxBodyBytes || len(t.URL) > MaxURLBytes || len(t.FullURI) > MaxURLBytes || len(t.Host) > MaxHeaderBytes || len(t.HeadersRaw) > MaxHeaderBytes || len(t.Headers) > MaxHeaders {
		return fmt.Errorf("request exceeds inspection limits")
	}
	for _, c := range t.URL {
		if c <= 32 || c == 127 {
			return fmt.Errorf("invalid URL characters")
		}
	}
	u, err := url.Parse(t.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return fmt.Errorf("only absolute HTTP(S) URLs without userinfo are supported")
	}
	if len(t.Method) > 32 || !validToken(t.Method) {
		return fmt.Errorf("invalid HTTP method")
	}
	for _, c := range t.Host {
		if c <= 32 || c == 127 {
			return fmt.Errorf("invalid HTTP host")
		}
	}
	count, size := 0, 0
	for k, vs := range t.Headers {
		if !validToken(k) {
			return fmt.Errorf("invalid HTTP header")
		}
		for _, v := range vs {
			count++
			size += len(k) + len(v) + 4
			for _, c := range v {
				if (c < 32 && c != '\t') || c == 127 {
					return fmt.Errorf("invalid HTTP header value")
				}
			}
			if strings.EqualFold(k, "Content-Encoding") && strings.TrimSpace(v) != "" && !strings.EqualFold(strings.TrimSpace(v), "identity") {
				return fmt.Errorf("encoded request bodies are not supported")
			}
		}
	}
	if count > MaxHeaders || size > MaxHeaderBytes {
		return fmt.Errorf("request exceeds inspection limits")
	}
	return nil
}
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

// Views and their optional ASCII-folded copies belong to one inspection only.
// Targets that expose the same bytes share a view, so hundreds of nocase rules
// cannot repeatedly allocate a body-sized folded string. Folding preserves byte
// offsets and never changes the raw bytes used by case-sensitive/PCRE matchers.
type inspectionView struct {
	raw, folded string
	hasFolded   bool
}

func (v *inspectionView) content(nocase bool) string {
	if !nocase {
		return v.raw
	}
	if !v.hasFolded {
		v.folded = asciiLower(v.raw)
		v.hasFolded = true
	}
	return v.folded
}

type inspectionBuffers map[TargetModifier][]*inspectionView

func sharedInspectionViews(raw map[TargetModifier][]string) inspectionBuffers {
	buffers := make(inspectionBuffers, len(raw))
	shared := map[string]*inspectionView{}
	for target, values := range raw {
		for _, value := range values {
			view := shared[value]
			if view == nil {
				view = &inspectionView{raw: value}
				shared[value] = view
			}
			buffers[target] = append(buffers[target], view)
		}
	}
	return buffers
}

func matchesBuffers(rule *Rule, buffers inspectionBuffers) bool {
	for _, co := range rule.Contents {
		// A missing field has no inspection buffer, including for negated rules.
		if len(buffers[co.Target]) == 0 {
			return false
		}
		neg := co.Negated
		co.Negated = false
		nocase := co.NoCase
		if nocase {
			co.Pattern = asciiLower(co.Pattern)
			co.NoCase = false
		}
		found := false
		for _, buf := range buffers[co.Target] {
			if matchContent(buf.content(nocase), co) {
				found = true
				break
			}
		}
		if found == neg {
			return false
		}
	}
	for _, po := range rule.PCREs {
		if len(buffers[po.Target]) == 0 {
			return false
		}
		found := false
		for _, buf := range buffers[po.Target] {
			if po.Regex != nil && po.Regex.MatchString(buf.raw) {
				found = true
				break
			}
		}
		if found == po.Negated {
			return false
		}
	}
	return true
}
func (e *Engine) matchesRule(rule *Rule, target *HTTPInspectionTarget) bool {
	buffers, err := buildBuffers(target)
	return err == nil && matchesBuffers(rule, buffers)
}
func matchContent(buf string, co ContentOption) bool {
	if co.Offset >= len(buf) && co.Offset > 0 {
		return co.Negated
	}
	if co.Offset > 0 {
		buf = buf[co.Offset:]
	}
	if co.Depth > 0 && len(buf) > co.Depth {
		buf = buf[:co.Depth]
	}
	pattern := co.Pattern
	if co.NoCase {
		buf = asciiLower(buf)
		pattern = asciiLower(pattern)
	}
	found := strings.Contains(buf, pattern)
	if co.Negated {
		return !found
	}
	return found
}

// normalizedViews retains raw bytes and caps both decoding work and expansion.
// It does not execute encodings, decompress bodies, or interpret base64 programs.
func normalizedViews(raw string, limit int) ([]string, error) {
	views := []string{raw}
	seen := map[string]bool{raw: true}
	total := len(raw)
	add := func(s string) error {
		if seen[s] {
			return nil
		}
		if len(views) >= maxViews || total+len(s) > 8*limit {
			return fmt.Errorf("request normalization exceeds inspection limits")
		}
		seen[s] = true
		total += len(s)
		views = append(views, s)
		return nil
	}
	// Extract valid JSON keys and string values in source order, including duplicate
	// keys. Full JSON validity is checked before tokens can become detection views.
	extract := func(s string) []string {
		if !json.Valid([]byte(s)) {
			return nil
		}
		var parts []string
		var canonical strings.Builder
		for i := 0; i < len(s); {
			if s[i] != '"' {
				canonical.WriteByte(s[i])
				i++
				continue
			}
			start := i
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
			var decoded string
			if err := json.Unmarshal([]byte(s[start:i]), &decoded); err != nil {
				return nil
			}
			parts = append(parts, decoded)
			canonical.WriteByte('"')
			canonical.WriteString(decoded)
			canonical.WriteByte('"')
		}
		if len(parts) == 0 {
			return nil
		}
		// This is a detection view, never an executable or forwarded document.
		// Retaining punctuation exposes encoded property names to structural rules.
		return []string{strings.Join(parts, "\n"), canonical.String()}
	}
	candidatesFor := func(s string) []string {
		candidates := []string{html.UnescapeString(s), decodePercent(s, false), decodePercent(s, true)}
		return append(candidates, extract(s)...)
	}
	frontier := []string{raw}
	for round := 0; round < 3; round++ {
		start := len(views)
		for _, s := range frontier {
			for _, v := range candidatesFor(s) {
				if err := add(v); err != nil {
					return nil, err
				}
			}
		}
		frontier = views[start:]
		if len(frontier) == 0 {
			break
		}
	}
	// The depth bound is a rejection boundary, not a silent truncation boundary.
	// One bounded probe detects undisclosed deeper views without retaining them
	// or extending the normalization loop.
	for _, s := range frontier {
		for _, candidate := range candidatesFor(s) {
			if !seen[candidate] {
				return nil, fmt.Errorf("request normalization depth exceeds inspection limits")
			}
		}
	}
	return views, nil
}
func buildBuffers(t *HTTPInspectionTarget) (inspectionBuffers, error) {
	// Raw request-target and body buffers must never gain decoded alternatives.
	buffers := map[TargetModifier][]string{TargetHTTPMethod: {t.Method}, TargetHTTPRawURI: {t.FullURI}, TargetHTTPRawBody: {t.Body}}
	for _, field := range []struct {
		target TargetModifier
		raw    string
		limit  int
	}{
		{TargetHTTPURI, t.URL, MaxURLBytes}, {TargetHTTPURI, t.FullURI, MaxURLBytes}, {TargetHTTPHeader, t.HeadersRaw, MaxHeaderBytes}, {TargetHTTPBody, t.Body, MaxBodyBytes},
	} {
		views, err := normalizedViews(field.raw, field.limit)
		if err != nil {
			return nil, err
		}
		buffers[field.target] = append(buffers[field.target], views...)
	}
	// Field selectors inspect values only, without the reconstructed header name.
	// Host is carried separately by net/http; req.Host overrides the URL authority.
	host := t.Host
	if host == "" {
		if u, err := url.Parse(t.URL); err == nil {
			host = u.Host
		}
	}
	values := map[string][]string{"host": {host}}
	for name, fieldValues := range t.Headers {
		name = strings.ToLower(name)
		if name != "host" {
			values[name] = append(values[name], fieldValues...)
		}
	}
	for name, fieldValues := range values {
		target := TargetModifier("http_header:field " + name)
		for _, value := range fieldValues {
			views, err := normalizedViews(value, MaxHeaderBytes)
			if err != nil {
				return nil, err
			}
			buffers[target] = append(buffers[target], views...)
		}
	}
	buffers[TargetAll] = []string{t.Method + " " + t.URL + " " + t.FullURI + "\n" + t.HeadersRaw + "\n" + t.Body}
	for _, target := range []TargetModifier{TargetHTTPURI, TargetHTTPHeader, TargetHTTPBody} {
		buffers[TargetAll] = append(buffers[TargetAll], buffers[target]...)
	}
	return sharedInspectionViews(buffers), nil
}

func BuildInspectionTarget(req *http.Request, body string) *HTTPInspectionTarget {
	fullURI := req.URL.RequestURI()
	var raw strings.Builder
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	raw.WriteString("Host: " + host + "\n")
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header[k] {
			raw.WriteString(k + ": " + v + "\n")
		}
	}
	return &HTTPInspectionTarget{Method: req.Method, URL: req.URL.String(), Path: req.URL.Path, Query: req.URL.RawQuery, FullURI: fullURI, Host: host, Headers: req.Header, HeadersRaw: raw.String(), Body: body, RemoteHost: req.URL.Hostname(), RemotePort: req.URL.Port()}
}

// Content nocase uses ASCII byte folding, preserving offsets and raw bytes.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// decodePercent retains malformed escapes while exposing valid ones. Aborting an
// entire decode on a stray '%' lets attackers hide otherwise valid escapes.
func decodePercent(s string, form bool) string {
	if !strings.Contains(s, "%") && (!form || !strings.Contains(s, "+")) {
		return s
	}
	hex := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			a, okA := hex(s[i+1])
			b, okB := hex(s[i+2])
			if okA && okB {
				out.WriteByte(a*16 + b)
				i += 2
				continue
			}
		}
		if form && s[i] == '+' {
			out.WriteByte(' ')
		} else {
			out.WriteByte(s[i])
		}
	}
	return out.String()
}
