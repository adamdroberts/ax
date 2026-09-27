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
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DefaultRulesSnort is the shared, versioned AX rule catalog (not full Snort).
//
//go:embed rules/default.rules
var DefaultRulesSnort string

// StrictRulesSnort contains optional policy restrictions with higher false positives.
//
//go:embed rules/strict.rules
var StrictRulesSnort string

// StrictActionsJSON promotes baseline advisory signatures without duplicating
// their detection logic in the strict catalog.
//
//go:embed rules/strict-actions.json
var StrictActionsJSON string

// DefaultEngine loads the baseline profile, including advisory alert rules.
func DefaultEngine() (*Engine, error) { return NewProfileEngine("default") }

// NewProfileEngine loads default rules, optionally followed by strict policy rules.
func NewProfileEngine(profile string) (*Engine, error) {
	if profile != "default" && profile != "strict" {
		return nil, fmt.Errorf("unknown rule profile %q", profile)
	}
	e := NewEngine()
	if _, err := e.LoadRulesFromReader(strings.NewReader(DefaultRulesSnort)); err != nil {
		return nil, err
	}
	if profile == "strict" {
		if _, err := e.LoadRulesFromReader(strings.NewReader(StrictRulesSnort)); err != nil {
			return nil, err
		}
		if err := e.applyStrictActions(strings.NewReader(StrictActionsJSON)); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// applyStrictActions validates the complete map before replacing any rule. Only
// alert-to-blocking promotions are valid; a profile cannot weaken a signature.
func (e *Engine) applyStrictActions(r io.Reader) error {
	decoder := json.NewDecoder(r)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("strict actions must be a JSON object")
	}
	actions := map[int]Action{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("reading strict action SID: %w", err)
		}
		key, ok := token.(string)
		sid64, err := strconv.ParseUint(key, 10, 31)
		sid := int(sid64)
		if !ok || err != nil || sid <= 0 || strconv.Itoa(sid) != key {
			return fmt.Errorf("invalid strict action SID %q", key)
		}
		if _, exists := actions[sid]; exists {
			return fmt.Errorf("duplicate strict action SID %d", sid)
		}
		var action Action
		if err := decoder.Decode(&action); err != nil {
			return fmt.Errorf("invalid strict action for SID %d: %w", sid, err)
		}
		if action != ActionDrop && action != ActionBlock && action != ActionReject {
			return fmt.Errorf("strict action for SID %d must block", sid)
		}
		actions[sid] = action
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("invalid strict action object ending")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected data after strict actions")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	indexes := map[int]int{}
	for i, rule := range e.rules {
		indexes[rule.SID] = i
	}
	for sid := range actions {
		i, exists := indexes[sid]
		if !exists {
			return fmt.Errorf("strict action references unknown SID %d", sid)
		}
		if e.rules[i].Action != ActionAlert {
			return fmt.Errorf("strict action SID %d must refer to an alert rule", sid)
		}
	}
	for sid, action := range actions {
		i := indexes[sid]
		updated := *e.rules[i]
		updated.Raw = string(action) + updated.Raw[len(updated.Action):]
		updated.Action = action
		e.rules[i] = &updated
	}
	return nil
}
