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

// ParseRules parses Snort rules from a reader.
func ParseRules(r io.Reader) ([]*Rule, error) {
	scanner := bufio.NewScanner(r)
	var rules []*Rule
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := ParseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading rules: %w", err)
	}
	return rules, nil
}

// ParseRule parses a single Snort rule string.
func ParseRule(raw string) (*Rule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil, nil
	}

	// Rule format: <action> <proto> <src_ip> <src_port> <dir> <dst_ip> <dst_port> (<options>)
	openParen := strings.Index(raw, "(")
	closeParen := strings.LastIndex(raw, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return nil, fmt.Errorf("missing rule options enclosure: %q", raw)
	}

	header := strings.TrimSpace(raw[:openParen])
	optionsStr := strings.TrimSpace(raw[openParen+1 : closeParen])

	fields := strings.Fields(header)
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid rule header (expected 7 fields, got %d): %q", len(fields), header)
	}

	action := Action(strings.ToLower(fields[0]))
	protocol := strings.ToLower(fields[1])
	srcIP := fields[2]
	srcPort := fields[3]
	direction := fields[4]
	dstIP := fields[5]
	dstPort := fields[6]

	rule := &Rule{
		Raw:       raw,
		Action:    action,
		Protocol:  protocol,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		Direction: direction,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Enabled:   true,
	}

	if err := parseOptions(rule, optionsStr); err != nil {
		return nil, fmt.Errorf("parsing options in rule %q: %w", raw, err)
	}

	return rule, nil
}

// parseOptions parses semicolon-delimited Snort options.
func parseOptions(rule *Rule, optionsStr string) error {
	opts := splitOptions(optionsStr)

	for _, opt := range opts {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}

		parts := strings.SplitN(opt, ":", 2)
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := ""
		if len(parts) == 2 {
			val = strings.TrimSpace(parts[1])
		}

		switch key {
		case "msg":
			rule.Message = trimQuotes(val)
		case "sid":
			sid, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid sid %q: %w", val, err)
			}
			rule.SID = sid
		case "rev":
			rev, err := strconv.Atoi(val)
			if err == nil {
				rule.Rev = rev
			}
		case "classtype":
			rule.ClassType = trimQuotes(val)
		case "content":
			co, err := parseContentOption(val)
			if err != nil {
				return err
			}
			rule.Contents = append(rule.Contents, co)
		case "nocase":
			if len(rule.Contents) > 0 {
				rule.Contents[len(rule.Contents)-1].NoCase = true
			}
		case "offset":
			if len(rule.Contents) > 0 {
				if off, err := strconv.Atoi(val); err == nil {
					rule.Contents[len(rule.Contents)-1].Offset = off
				}
			}
		case "depth":
			if len(rule.Contents) > 0 {
				if d, err := strconv.Atoi(val); err == nil {
					rule.Contents[len(rule.Contents)-1].Depth = d
				}
			}
		case "http_uri", "uricontent":
			applyTargetModifier(rule, TargetHTTPURI)
		case "http_header":
			applyTargetModifier(rule, TargetHTTPHeader)
		case "http_client_body":
			applyTargetModifier(rule, TargetHTTPBody)
		case "http_method":
			applyTargetModifier(rule, TargetHTTPMethod)
		case "pcre":
			po, err := parsePCREOption(val)
			if err != nil {
				return err
			}
			rule.PCREs = append(rule.PCREs, po)
		}
	}

	return nil
}

// splitOptions splits an options string on semicolons, taking quotes into account.
func splitOptions(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			current.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			current.WriteByte(ch)
			continue
		}
		if ch == ';' && !inQuotes {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		return s[1 : len(s)-1]
	}
	return s
}

// parseContentOption parses content pattern, handling negation and hex notation (e.g. |0d 0a|).
func parseContentOption(val string) (ContentOption, error) {
	val = strings.TrimSpace(val)
	negated := false
	if strings.HasPrefix(val, "!") {
		negated = true
		val = strings.TrimSpace(val[1:])
	}

	rawPattern := trimQuotes(val)
	pattern, err := decodeSnortHex(rawPattern)
	if err != nil {
		return ContentOption{}, fmt.Errorf("decoding hex in content %q: %w", rawPattern, err)
	}

	return ContentOption{
		Pattern: pattern,
		Negated: negated,
		Target:  TargetAll,
	}, nil
}

// decodeSnortHex converts Snort hex representations |41 42| to their ASCII/raw byte equivalent.
func decodeSnortHex(s string) (string, error) {
	var sb strings.Builder
	for {
		start := strings.Index(s, "|")
		if start == -1 {
			sb.WriteString(s)
			break
		}
		sb.WriteString(s[:start])
		s = s[start+1:]
		end := strings.Index(s, "|")
		if end == -1 {
			return "", fmt.Errorf("unclosed hex pipe: |%s", s)
		}
		hexStr := strings.ReplaceAll(s[:end], " ", "")
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			return "", fmt.Errorf("invalid hex string %q: %w", hexStr, err)
		}
		sb.Write(decoded)
		s = s[end+1:]
	}
	return sb.String(), nil
}

// parsePCREOption parses a pcre option: "[!]/regex/[flags]".
func parsePCREOption(val string) (PCREOption, error) {
	val = strings.TrimSpace(val)
	negated := false
	if strings.HasPrefix(val, "!") {
		negated = true
		val = strings.TrimSpace(val[1:])
	}
	val = trimQuotes(val)

	// Format: /pattern/flags
	if !strings.HasPrefix(val, "/") {
		return PCREOption{}, fmt.Errorf("invalid pcre format (must start with /): %q", val)
	}

	lastSlash := strings.LastIndex(val, "/")
	if lastSlash <= 0 {
		return PCREOption{}, fmt.Errorf("invalid pcre format (missing terminating /): %q", val)
	}

	pattern := val[1:lastSlash]
	flags := val[lastSlash+1:]

	goRegexPattern := ""
	for _, f := range flags {
		switch f {
		case 'i':
			goRegexPattern += "(?i)"
		case 's':
			goRegexPattern += "(?s)"
		case 'm':
			goRegexPattern += "(?m)"
		}
	}
	goRegexPattern += pattern

	re, err := regexp.Compile(goRegexPattern)
	if err != nil {
		return PCREOption{}, fmt.Errorf("compiling pcre regex %q: %w", goRegexPattern, err)
	}

	return PCREOption{
		RawRegex: val,
		Regex:    re,
		Negated:  negated,
		Target:   TargetAll,
	}, nil
}

func applyTargetModifier(rule *Rule, target TargetModifier) {
	if len(rule.PCREs) > 0 {
		rule.PCREs[len(rule.PCREs)-1].Target = target
		return
	}
	if len(rule.Contents) > 0 {
		rule.Contents[len(rule.Contents)-1].Target = target
	}
}
