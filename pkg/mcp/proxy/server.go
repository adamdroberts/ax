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

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/ax/pkg/security/egress"
	"github.com/google/ax/pkg/security/httpguard"
	"github.com/google/ax/pkg/security/snort"
)

const (
	ProtocolVersion = "2024-11-05"
	ServerName      = "ax-mcp-proxy"
	ServerVersion   = "1.0.0"

	MaxResponseBodyBytes  = 10 * 1024 * 1024 // 10 MiB
	MaxSessionInspections = 1000
	MaxSessionBytes       = 64 * 1024 * 1024
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError defines a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ToolCallResult represents an MCP tool execution result.
type ToolCallResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent is a single content element inside a ToolCallResult.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Stats tracks security proxy activity.
type Stats struct {
	TotalInspected uint64 `json:"total_inspected"`
	TotalPassed    uint64 `json:"total_passed"`
	TotalBlocked   uint64 `json:"total_blocked"`
}

// Server is the Model Context Protocol security proxy server.
type Server struct {
	engine             *snort.Engine
	httpClient         *http.Client
	allowedOrigins     []string
	originsConfigured  bool
	egressPolicy       *egress.Policy
	customClient       bool
	inspectionAttempts uint64
	inspectionBytes    uint64
	responseBytes      uint64
	rpcMessages        uint64
	rpcBytes           uint64
	stats              Stats
	mu                 sync.Mutex
	transportMu        sync.Mutex
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithHTTPClient is a TRUSTED embedding/testing escape hatch: its transport is
// responsible for DNS/IP enforcement. It bypasses the default origin policy unless
// WithAllowedOrigins is also provided. Never expose this option to agent input.
// Redirects and automatic cookies are still disabled on a copy.
func WithHTTPClient(client *http.Client) ServerOption {
	return func(s *Server) {
		s.httpClient = client
		s.customClient = true
	}
}

// WithAllowedOrigins configures exact administrator-owned outbound origins.
// An empty list denies all egress. No wildcard or request-level overrides exist.
func WithAllowedOrigins(origins ...string) ServerOption {
	return func(s *Server) { s.allowedOrigins = append([]string(nil), origins...); s.originsConfigured = true }
}

// WithEngine sets the Snort engine.
func WithEngine(engine *snort.Engine) ServerOption {
	return func(s *Server) {
		s.engine = engine
	}
}

// NewServer creates a new MCP Security Proxy Server.
func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{}

	for _, opt := range opts {
		opt(s)
	}

	if s.engine == nil {
		eng, err := snort.DefaultEngine()
		if err != nil {
			return nil, fmt.Errorf("initializing default snort engine: %w", err)
		}
		s.engine = eng
	}

	if s.customClient && s.httpClient == nil {
		return nil, fmt.Errorf("HTTP client must not be nil")
	}
	if s.httpClient == nil {
		var err error
		s.httpClient, err = egress.NewClient(s.allowedOrigins)
		if err != nil {
			return nil, err
		}
		s.originsConfigured = true
	}
	if s.originsConfigured {
		var err error
		s.egressPolicy, err = egress.NewPolicy(s.allowedOrigins)
		if err != nil {
			return nil, err
		}
	}
	// Never follow an uninspected redirect or let a cookie jar add headers after
	// inspection. Copy the client to preserve the caller's configuration.
	client := *s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	s.httpClient = &client

	return s, nil
}

// Serve reads JSON-RPC messages from in and writes responses to out until EOF or error.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Bound the wire envelope independently of decoded request fields.
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 8*1024*1024+1)

	encoder := json.NewEncoder(out)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if atomic.AddUint64(&s.rpcMessages, 1) > 10000 || atomic.AddUint64(&s.rpcBytes, uint64(len(line))) > MaxSessionBytes {
			return fmt.Errorf("process RPC input budget exhausted")
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := decodeRequest(line, &req); err != nil {
			code := -32600
			if !json.Valid(line) || !utf8.Valid(line) {
				code = -32700
			}
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    code,
					Message: "Invalid JSON-RPC request",
				},
			}
			s.mu.Lock()
			_ = encoder.Encode(resp)
			s.mu.Unlock()
			continue
		}

		resp := s.handleRequest(ctx, &req)
		if resp != nil {
			s.mu.Lock()
			if err := encoder.Encode(resp); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("encoding response: %w", err)
			}
			s.mu.Unlock()
		}
	}

	return scanner.Err()
}

func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Notifications (no ID) do not require a response unless error
	isNotification := req.ID == nil
	// MCP tool operations require an ID. A notification must never cause an
	// unacknowledged network side effect.
	if isNotification {
		return nil
	}

	switch req.Method {
	case "initialize":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": ProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    ServerName,
					"version": ServerVersion,
				},
			},
		}

	case "notifications/initialized":
		// Standard MCP client acknowledgement notification
		return nil

	case "ping":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}

	case "tools/call":
		res, err := s.handleToolCall(ctx, req.Params)
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   err,
			}
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  res,
		}

	default:
		if isNotification {
			return nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    -32601,
				Message: fmt.Sprintf("Method %q not found", req.Method),
			},
		}
	}
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Server) handleToolCall(ctx context.Context, rawParams json.RawMessage) (*ToolCallResult, *JSONRPCError) {
	var p toolCallParams
	if err := httpguard.ValidateJSON(rawParams); err != nil {
		return nil, &JSONRPCError{Code: -32602, Message: "Invalid params"}
	}
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(rawParams, &properties); err != nil || properties == nil {
		return nil, &JSONRPCError{Code: -32602, Message: "Tool params must be an object"}
	}
	for key := range properties {
		if key != "name" && key != "arguments" && key != "_meta" {
			return nil, &JSONRPCError{Code: -32602, Message: "Unknown tool param"}
		}
	}
	if meta, exists := properties["_meta"]; exists && (len(meta) == 0 || meta[0] != '{') {
		return nil, &JSONRPCError{Code: -32602, Message: "Tool metadata must be an object"}
	}
	if err := json.Unmarshal(rawParams, &p); err != nil || p.Name == "" {
		return nil, &JSONRPCError{
			Code:    -32602,
			Message: "Invalid tool params",
		}
	}
	if raw, exists := properties["arguments"]; exists && (len(raw) == 0 || raw[0] != '{') {
		return nil, &JSONRPCError{Code: -32602, Message: "Tool arguments must be an object"}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	switch p.Name {
	case "http_request":
		return s.executeHTTPRequest(ctx, p.Arguments)
	case "check_security_payload":
		return s.executeCheckPayload(p.Arguments)
	case "get_security_stats":
		if len(p.Arguments) != 0 {
			return nil, &JSONRPCError{Code: -32602, Message: "Statistics tool has no arguments"}
		}
		return s.executeGetStats()
	default:
		return nil, &JSONRPCError{
			Code:    -32601,
			Message: fmt.Sprintf("Unknown tool: %s", p.Name),
		}
	}
}

// buildHTTPRequest is shared by dispatch and diagnostics so an input cannot
// pass one path and be interpreted differently by the other.
func buildHTTPRequest(ctx context.Context, args map[string]any) (*http.Request, string, time.Duration, error) {
	for key := range args {
		switch key {
		case "url", "method", "body", "headers", "timeout_seconds":
		default:
			return nil, "", 0, fmt.Errorf("unknown request argument")
		}
	}
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return nil, "", 0, fmt.Errorf("a non-empty string 'url' is required")
	}
	if len(rawURL) > snort.MaxURLBytes {
		return nil, "", 0, fmt.Errorf("URL exceeds the 16 KiB inspection limit")
	}
	if err := httpguard.ValidateURL(rawURL); err != nil {
		return nil, "", 0, err
	}

	method := "GET"
	if value, exists := args["method"]; exists {
		m, ok := value.(string)
		if !ok || m == "" {
			return nil, "", 0, fmt.Errorf("method must be a non-empty string")
		}
		method = m
	}
	body := ""
	if value, exists := args["body"]; exists {
		var ok bool
		body, ok = value.(string)
		if !ok {
			return nil, "", 0, fmt.Errorf("body must be a string")
		}
	}
	if len(body) > snort.MaxBodyBytes {
		return nil, "", 0, fmt.Errorf("body exceeds the 1 MiB inspection limit")
	}

	timeout := 30 * time.Second
	if value, exists := args["timeout_seconds"]; exists {
		seconds, ok := value.(float64)
		if !ok || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 1 || seconds > 120 || math.Trunc(seconds) != seconds {
			return nil, "", 0, fmt.Errorf("timeout_seconds must be an integer between 1 and 120")
		}
		timeout = time.Duration(seconds) * time.Second
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		// net/http errors can include the URL, including query credentials.
		return nil, "", 0, fmt.Errorf("invalid HTTP request parameters")
	}
	if value, exists := args["headers"]; exists {
		headers, ok := value.(map[string]any)
		if !ok {
			return nil, "", 0, fmt.Errorf("headers must be an object containing string values")
		}
		if len(headers) > snort.MaxHeaders {
			return nil, "", 0, fmt.Errorf("headers exceed the 128 header inspection limit")
		}
		headerBytes := 0
		seen := make(map[string]bool, len(headers))
		for name, value := range headers {
			text, ok := value.(string)
			if !ok {
				return nil, "", 0, fmt.Errorf("invalid HTTP header name or value")
			}
			if err := httpguard.ValidateHeader(name, text); err != nil {
				return nil, "", 0, err
			}
			headerBytes += len(name) + len(text) + 4
			if headerBytes > snort.MaxHeaderBytes {
				return nil, "", 0, fmt.Errorf("headers exceed the 64 KiB inspection limit")
			}
			key := strings.ToLower(name)
			if seen[key] {
				return nil, "", 0, fmt.Errorf("duplicate HTTP header names are not permitted")
			}
			seen[key] = true
			req.Header.Set(name, text)
		}
	}
	if err := httpguard.Prepare(req, body); err != nil {
		return nil, "", 0, err
	}
	return req, body, timeout, nil
}

func (s *Server) inspectArguments(ctx context.Context, args map[string]any) (*http.Request, time.Duration, snort.MatchResult) {
	if atomic.AddUint64(&s.inspectionAttempts, 1) > MaxSessionInspections {
		return nil, 0, snort.MatchResult{Blocked: true, Action: snort.ActionBlock, Reason: "process inspection count budget exhausted"}
	}
	if atomic.LoadUint64(&s.responseBytes) >= MaxSessionBytes {
		return nil, 0, snort.MatchResult{Blocked: true, Action: snort.ActionBlock, Reason: "process response byte budget exhausted"}
	}
	req, body, timeout, err := buildHTTPRequest(ctx, args)
	if err != nil {
		return nil, 0, snort.MatchResult{Blocked: true, Action: snort.ActionBlock, Reason: err.Error()}
	}
	inspectedBytes := len(req.URL.String()) + len(body)
	for name, values := range req.Header {
		for _, value := range values {
			inspectedBytes += len(name) + len(value) + 4
		}
	}
	if atomic.AddUint64(&s.inspectionBytes, uint64(inspectedBytes)) > MaxSessionBytes {
		return nil, 0, snort.MatchResult{Blocked: true, Action: snort.ActionBlock, Reason: "process inspection byte budget exhausted"}
	}
	match := s.engine.InspectHTTPRequest(req, []byte(body))
	if !match.Blocked && s.egressPolicy != nil {
		if err := s.egressPolicy.CheckURL(req.URL.String()); err != nil {
			return nil, 0, snort.MatchResult{Blocked: true, Action: snort.ActionBlock, Reason: "destination is not allowed by the configured egress policy"}
		}
	}
	return req, timeout, match
}

func toolError(message string) (*ToolCallResult, *JSONRPCError) {
	return &ToolCallResult{IsError: true, Content: []ToolContent{{Type: "text", Text: message}}}, nil
}

func (s *Server) executeHTTPRequest(ctx context.Context, args map[string]any) (*ToolCallResult, *JSONRPCError) {
	// Stdio is serial; retain that invariant for trusted concurrent embedders so
	// response budgets cannot be oversubscribed by parallel body readers.
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	atomic.AddUint64(&s.stats.TotalInspected, 1)
	httpReq, timeout, match := s.inspectArguments(ctx, args)
	if match.Blocked {
		atomic.AddUint64(&s.stats.TotalBlocked, 1)
		// Record policy identifiers only; URLs, bodies and headers may contain
		// secrets even when the request is blocked.
		sid := 0
		if match.MatchedRule != nil {
			sid = match.MatchedRule.SID
		}
		slog.Warn("outbound request blocked by security policy", "sid", sid, "validation_failure", match.MatchedRule == nil)
		return toolError(fmt.Sprintf("SECURITY VIOLATION: Outbound request blocked by policy. Reason: %s (Action: %s)", match.Reason, match.Action))
	}
	if match.Matched && match.MatchedRule != nil {
		slog.Info("outbound request matched security advisory", "sid", match.MatchedRule.SID, "action", match.Action)
	}
	atomic.AddUint64(&s.stats.TotalPassed, 1)

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq = httpReq.WithContext(reqCtx)
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return toolError("Request failed during HTTP transport")
	}
	defer resp.Body.Close()

	// Read one extra byte to distinguish a complete response from truncation.
	remaining := int64(MaxSessionBytes) - int64(atomic.LoadUint64(&s.responseBytes))
	limit := int64(MaxResponseBodyBytes)
	if remaining < limit {
		limit = remaining
	}
	if limit < 0 {
		return toolError("Process response byte budget exhausted")
	}
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if atomic.AddUint64(&s.responseBytes, uint64(len(respBytes))) > MaxSessionBytes {
		return toolError("Process response byte budget exhausted")
	}
	if err != nil {
		return toolError("Reading response body failed")
	}
	if len(respBytes) > MaxResponseBodyBytes {
		return toolError("Response body exceeds the 10 MiB limit")
	}
	if !utf8.Valid(respBytes) {
		return toolError("Response body is not UTF-8 text")
	}
	if err := egress.CheckResponseBody(resp, httpReq.Method, respBytes); err != nil {
		return toolError("Response body failed content validation")
	}

	outHeaders := make(map[string]any)
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			outHeaders[k] = v
		} else {
			outHeaders[k] = strings.Join(v, ", ")
		}
	}
	summary := map[string]any{
		"status_code":   resp.StatusCode,
		"status":        resp.Status,
		"headers":       outHeaders,
		"header_values": resp.Header,
		"body":          string(respBytes),
	}
	encoded, _ := json.MarshalIndent(summary, "", "  ")
	return &ToolCallResult{
		IsError: resp.StatusCode >= 400,
		Content: []ToolContent{{Type: "text", Text: string(encoded)}},
	}, nil
}

func (s *Server) executeCheckPayload(args map[string]any) (*ToolCallResult, *JSONRPCError) {
	_, _, match := s.inspectArguments(context.Background(), args)
	res := map[string]any{"blocked": match.Blocked, "matched": match.Matched, "dns_checked": false}
	if match.Reason != "" {
		res["reason"] = match.Reason
	}
	if match.Blocked || match.Matched {
		res["action"] = string(match.Action)
	}
	if match.MatchedRule != nil {
		res["rule_sid"] = match.MatchedRule.SID
		res["rule_msg"] = match.MatchedRule.Message
		res["classtype"] = match.MatchedRule.ClassType
	}
	encoded, _ := json.MarshalIndent(res, "", "  ")
	return &ToolCallResult{Content: []ToolContent{{Type: "text", Text: string(encoded)}}}, nil
}

func (s *Server) executeGetStats() (*ToolCallResult, *JSONRPCError) {
	stats := map[string]any{
		"total_inspected":     atomic.LoadUint64(&s.stats.TotalInspected),
		"total_passed":        atomic.LoadUint64(&s.stats.TotalPassed),
		"total_blocked":       atomic.LoadUint64(&s.stats.TotalBlocked),
		"rules_loaded":        s.engine.RuleCount(),
		"inspection_attempts": atomic.LoadUint64(&s.inspectionAttempts),
		"inspection_bytes":    atomic.LoadUint64(&s.inspectionBytes),
		"response_bytes":      atomic.LoadUint64(&s.responseBytes),
	}
	encoded, _ := json.MarshalIndent(stats, "", "  ")
	return &ToolCallResult{
		Content: []ToolContent{{Type: "text", Text: string(encoded)}},
	}, nil
}

func (s *Server) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "http_request",
			"description": "Sends inspected HTTP requests to administrator-approved origins under strict protocol, destination and resource policies. Other tools require independent network confinement.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "Absolute ASCII HTTP(S) URL on an administrator-approved origin; maximum 16 KiB, no userinfo or fragments",
					},
					"method": map[string]any{
						"type":        "string",
						"description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)",
						"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
						"default":     "GET",
					},
					"headers": map[string]any{
						"type":                 "object",
						"description":          "ASCII HTTP header values; up to 128 fields, 8 KiB each, 64 KiB total. Framing, routing and browser-context headers are managed by policy.",
						"additionalProperties": map[string]any{"type": "string"},
					},
					"body": map[string]any{
						"type":        "string",
						"description": "UTF-8 plain text, JSON or form data, maximum 1 MiB; GET/HEAD bodies and compressed or opaque media are unsupported",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds, between 1 and 120 (default: 30)",
						"default":     30,
						"minimum":     1,
						"maximum":     120,
					},
				},
				"required":             []string{"url"},
				"additionalProperties": false,
			},
		},
		{
			"name":        "check_security_payload",
			"description": "Checks request syntax, signatures and configured origins without network traffic; DNS and TLS are checked only during dispatch. Diagnostics consume inspection capacity.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "Absolute HTTP(S) URL to inspect (maximum 16 KiB, no userinfo)",
					},
					"method": map[string]any{
						"type":    "string",
						"default": "GET",
						"enum":    []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
					},
					"headers": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string"},
					},
					"body": map[string]any{
						"type": "string",
					},
					"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 120, "default": 30},
				},
				"required":             []string{"url"},
				"additionalProperties": false,
			},
		},
		{
			"name":        "get_security_stats",
			"description": "Returns operational statistics on requests inspected, passed, and blocked by Snort rules.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
	}
}
