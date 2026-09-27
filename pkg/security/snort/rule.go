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
	"regexp"
)

// Action defines what happens when a rule matches.
type Action string

const (
	ActionAlert  Action = "alert"
	ActionDrop   Action = "drop"
	ActionBlock  Action = "block"
	ActionReject Action = "reject"
	ActionPass   Action = "pass"
)

// TargetModifier specifies which part of the HTTP request a content or PCRE option targets.
type TargetModifier string

const (
	TargetAll         TargetModifier = "all"
	TargetHTTPURI     TargetModifier = "http_uri"
	TargetHTTPRawURI  TargetModifier = "http_raw_uri"
	TargetHTTPHeader  TargetModifier = "http_header"
	TargetHTTPBody    TargetModifier = "http_client_body"
	TargetHTTPRawBody TargetModifier = "http_raw_body"
	TargetHTTPMethod  TargetModifier = "http_method"
)

// ContentOption represents a `content` keyword in a Snort rule.
type ContentOption struct {
	Pattern string
	Negated bool
	NoCase  bool
	Offset  int
	Depth   int
	Target  TargetModifier
}

// PCREOption represents a `pcre` keyword in a Snort rule.
type PCREOption struct {
	RawRegex string
	Regex    *regexp.Regexp
	Negated  bool
	Target   TargetModifier
}

// Rule represents a parsed Snort intrusion detection/prevention rule.
type Rule struct {
	Raw       string
	Action    Action
	Protocol  string
	SrcIP     string
	SrcPort   string
	Direction string
	DstIP     string
	DstPort   string
	SID       int
	Rev       int
	Message   string
	ClassType string
	Contents  []ContentOption
	PCREs     []PCREOption
	Enabled   bool
}

// String returns a human-readable representation of the Rule.
func (r *Rule) String() string {
	return fmt.Sprintf("[SID %d] %s: %s (Action: %s)", r.SID, r.ClassType, r.Message, r.Action)
}

// HTTPInspectionTarget contains the extracted, normalized components of an HTTP request.
type HTTPInspectionTarget struct {
	Method     string
	URL        string
	Path       string
	Query      string
	FullURI    string
	Host       string
	Headers    map[string][]string
	HeadersRaw string
	Body       string
	RemoteHost string
	RemotePort string
}

// MatchResult describes the outcome of evaluating rules against a request target.
type MatchResult struct {
	Matched     bool
	Action      Action
	Blocked     bool
	MatchedRule *Rule
	Reason      string
}
