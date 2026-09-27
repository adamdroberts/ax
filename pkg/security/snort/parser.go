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
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// ParseRules accepts the documented AX subset, never silently ignoring options.
func ParseRules(r io.Reader) ([]*Rule, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	var rules []*Rule
	seen := map[int]bool{}
	for line := 1; scanner.Scan(); line++ {
		rule, err := ParseRule(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if rule == nil {
			continue
		}
		if seen[rule.SID] {
			return nil, fmt.Errorf("line %d: duplicate SID %d", line, rule.SID)
		}
		seen[rule.SID] = true
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading rules: %w", err)
	}
	return rules, nil
}

func ParseRule(raw string) (*Rule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil, nil
	}
	open, close := strings.Index(raw, "("), strings.LastIndex(raw, ")")
	if open < 0 || close <= open || strings.TrimSpace(raw[close+1:]) != "" {
		return nil, fmt.Errorf("invalid rule enclosure")
	}
	fields := strings.Fields(raw[:open])
	if len(fields) != 7 {
		return nil, fmt.Errorf("rule header must contain exactly 7 fields")
	}
	action := Action(strings.ToLower(fields[0]))
	switch action {
	case ActionAlert, ActionDrop, ActionReject, ActionBlock:
	default:
		return nil, fmt.Errorf("unsupported action %q", fields[0])
	}
	protocol := strings.ToLower(fields[1])
	if protocol != "tcp" && protocol != "http" {
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	if fields[2] != "any" || fields[3] != "any" || fields[4] != "->" || fields[5] != "any" || fields[6] != "any" {
		return nil, fmt.Errorf("AX only supports the header: tcp/http any any -> any any")
	}
	rule := &Rule{Raw: raw, Action: action, Protocol: protocol, SrcIP: "any", SrcPort: "any", Direction: "->", DstIP: "any", DstPort: "any", Rev: 1, Enabled: true}
	if err := parseOptions(rule, raw[open+1:close]); err != nil {
		return nil, err
	}
	if rule.SID <= 0 {
		return nil, fmt.Errorf("a positive sid is required")
	}
	if len(rule.Contents)+len(rule.PCREs) == 0 {
		return nil, fmt.Errorf("at least one content or pcre matcher is required")
	}
	return rule, nil
}

func parseOptions(rule *Rule, input string) error {
	opts, err := splitOptions(input)
	if err != nil {
		return err
	}
	last := ""
	seen := map[string]bool{}
	modifiers := map[string]bool{}
	for _, opt := range opts {
		parts := strings.SplitN(strings.TrimSpace(opt), ":", 2)
		key, val := strings.ToLower(strings.TrimSpace(parts[0])), ""
		if key == "" {
			continue
		}
		hasValue := len(parts) == 2
		if hasValue {
			val = strings.TrimSpace(parts[1])
		}
		switch key {
		case "msg", "sid", "rev", "classtype":
			if !hasValue || seen[key] {
				return fmt.Errorf("missing or duplicate %s", key)
			}
			seen[key] = true
			switch key {
			case "msg":
				v, err := quoted(val)
				if err != nil {
					return err
				}
				rule.Message = v
			case "classtype":
				if strings.HasPrefix(val, `"`) {
					v, err := quoted(val)
					if err != nil {
						return err
					}
					val = v
				}
				if valid, _ := regexp.MatchString(`^[A-Za-z0-9_-]+$`, val); !valid {
					return fmt.Errorf("invalid classtype")
				}
				rule.ClassType = val
			case "sid", "rev":
				n64, err := strconv.ParseUint(val, 10, 31)
				n := int(n64)
				if err != nil || n <= 0 || strings.HasPrefix(val, "+") {
					return fmt.Errorf("invalid %s", key)
				}
				if key == "sid" {
					rule.SID = n
				} else {
					rule.Rev = n
				}
			}
		case "content":
			co, err := parseContentOption(val)
			if err != nil {
				return err
			}
			rule.Contents = append(rule.Contents, co)
			last = key
			modifiers = map[string]bool{}
		case "pcre":
			po, err := parsePCREOption(val)
			if err != nil {
				return err
			}
			rule.PCREs = append(rule.PCREs, po)
			last = key
			modifiers = map[string]bool{}
		case "nocase", "offset", "depth", "http_uri", "http_raw_uri", "http_header", "http_client_body", "http_raw_body", "http_method":
			if last == "" {
				return fmt.Errorf("%s must follow a matcher", key)
			}
			if modifiers[key] {
				return fmt.Errorf("duplicate modifier %s", key)
			}
			modifiers[key] = true
			switch key {
			case "nocase", "offset", "depth":
				if last != "content" {
					return fmt.Errorf("%s requires content (pcre uses /i)", key)
				}
				co := &rule.Contents[len(rule.Contents)-1]
				if key == "nocase" {
					if hasValue {
						return fmt.Errorf("nocase has no value")
					}
					co.NoCase = true
				} else {
					n, err := strconv.Atoi(val)
					if err != nil || n < 0 || !hasValue || (key == "depth" && n == 0) {
						return fmt.Errorf("invalid %s", key)
					}
					if key == "offset" {
						co.Offset = n
					} else {
						co.Depth = n
					}
				}
			default:
				if modifiers["target"] {
					return fmt.Errorf("invalid or multiple HTTP target modifiers")
				}
				target := TargetModifier(key)
				if hasValue {
					field := strings.Fields(val)
					if key != "http_header" || len(field) != 2 || field[0] != "field" || !validToken(field[1]) {
						return fmt.Errorf("invalid HTTP target modifier value")
					}
					target = TargetModifier("http_header:field " + strings.ToLower(field[1]))
				}
				modifiers["target"] = true
				if last == "content" {
					rule.Contents[len(rule.Contents)-1].Target = target
				} else {
					rule.PCREs[len(rule.PCREs)-1].Target = target
				}
			}
		default:
			return fmt.Errorf("unsupported rule option %q", key)
		}
	}
	return nil
}

// splitOptions preserves regex escaping and requires complete quoted options.
func splitOptions(s string) ([]string, error) {
	var result []string
	start, inQuotes, escaped := 0, false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
		}
		if ch == ';' && !inQuotes {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if inQuotes || escaped {
		return nil, fmt.Errorf("unterminated quoted or escaped option")
	}
	if strings.TrimSpace(s[start:]) != "" {
		return nil, fmt.Errorf("rule options must end in a semicolon")
	}
	return result, nil
}

func quoted(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("expected quoted value")
	}
	inner := s[1 : len(s)-1]
	escaped := false
	for i := 0; i < len(inner); i++ {
		if escaped {
			escaped = false
			continue
		}
		if inner[i] == '\\' {
			escaped = true
		} else if inner[i] == '"' {
			return "", fmt.Errorf("unescaped quote")
		}
	}
	if escaped {
		return "", fmt.Errorf("unterminated escape")
	}
	return inner, nil
}

func parseContentOption(val string) (ContentOption, error) {
	negated := strings.HasPrefix(val, "!")
	if negated {
		val = strings.TrimSpace(val[1:])
	}
	raw, err := quoted(val)
	if err != nil {
		return ContentOption{}, err
	}
	pattern, err := decodeSnortHex(raw)
	if err != nil {
		return ContentOption{}, err
	}
	if pattern == "" {
		return ContentOption{}, fmt.Errorf("empty content")
	}
	return ContentOption{Pattern: pattern, Negated: negated, Target: TargetAll}, nil
}

func decodeSnortHex(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			if i >= len(s) || !strings.ContainsRune(`\";:|`, rune(s[i])) {
				return "", fmt.Errorf("unsupported content escape")
			}
			out.WriteByte(s[i])
		case '|':
			end := strings.IndexByte(s[i+1:], '|')
			if end < 0 {
				return "", fmt.Errorf("unclosed hex pipe")
			}
			data, err := hex.DecodeString(strings.Join(strings.Fields(s[i+1:i+1+end]), ""))
			if err != nil || len(data) == 0 {
				return "", fmt.Errorf("invalid hex content")
			}
			out.Write(data)
			i += end + 1
		default:
			out.WriteByte(s[i])
		}
	}
	return out.String(), nil
}

func parsePCREOption(val string) (PCREOption, error) {
	negated := strings.HasPrefix(val, "!")
	if negated {
		val = strings.TrimSpace(val[1:])
	}
	raw, err := quoted(val)
	if err != nil {
		return PCREOption{}, err
	}
	last := strings.LastIndex(raw, "/")
	if !strings.HasPrefix(raw, "/") || last <= 1 {
		return PCREOption{}, fmt.Errorf("expected nonempty /regex/flags")
	}
	pattern, flags := raw[1:last], raw[last+1:]
	seen := map[rune]bool{}
	for _, flag := range flags {
		if !strings.ContainsRune("ism", flag) || seen[flag] {
			return PCREOption{}, fmt.Errorf("unsupported or duplicate pcre flag %q", flag)
		}
		seen[flag] = true
	}
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return PCREOption{}, fmt.Errorf("invalid RE2 pcre: %w", err)
	}
	return PCREOption{RawRegex: raw, Regex: re, Negated: negated, Target: TargetAll}, nil
}
