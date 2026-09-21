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
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/ax/pkg/security/snort"
)

const (
	ProtocolVersion = "2024-11-05"
	ServerName      = "ax-mcp-proxy"
	ServerVersion   = "1.0.0"

	MaxResponseBodyBytes = 10 * 1024 * 1024 // 10 MB
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
	ID      any           `json:"id,omitempty"`
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
	engine     *snort.Engine
	httpClient *http.Client
	stats      Stats
	mu         sync.Mutex
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithHTTPClient overrides the default HTTP client used for proxying.
func WithHTTPClient(client *http.Client) ServerOption {
	return func(s *Server) {
		s.httpClient = client
	}
}

// WithEngine sets the Snort engine.
func WithEngine(engine *snort.Engine) ServerOption {
	return func(s *Server) {
		s.engine = engine
	}
}

// NewServer creates a new MCP Security Proxy Server.
func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

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

	return s, nil
}

// Serve reads JSON-RPC messages from in and writes responses to out until EOF or error.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Support larger payloads up to 16MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 16*1024*1024)

	encoder := json.NewEncoder(out)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    -32700,
					Message: "Parse error",
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
	if err := json.Unmarshal(rawParams, &p); err != nil {
		return nil, &JSONRPCError{
			Code:    -32602,
			Message: "Invalid params: " + err.Error(),
		}
	}

	switch p.Name {
	case "http_request":
		return s.executeHTTPRequest(ctx, p.Arguments)
	case "check_security_payload":
		return s.executeCheckPayload(p.Arguments)
	case "get_security_stats":
		return s.executeGetStats()
	default:
		return nil, &JSONRPCError{
			Code:    -32601,
			Message: fmt.Sprintf("Unknown tool: %s", p.Name),
		}
	}
}

func (s *Server) executeHTTPRequest(ctx context.Context, args map[string]any) (*ToolCallResult, *JSONRPCError) {
	atomic.AddUint64(&s.stats.TotalInspected, 1)

	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Missing required argument 'url'"}},
		}, nil
	}

	method := "GET"
	if m, ok := args["method"].(string); ok && m != "" {
		method = strings.ToUpper(m)
	}

	bodyStr := ""
	if b, ok := args["body"].(string); ok {
		bodyStr = b
	}

	headers := make(map[string]string)
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			if vs, ok := v.(string); ok {
				headers[k] = vs
			}
		}
	}

	timeoutSec := 30
	if ts, ok := args["timeout_seconds"].(float64); ok && ts > 0 {
		timeoutSec = int(ts)
	}

	// 1. Build and Inspect HTTP request with Snort Engine
	httpReq, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(bodyStr))
	if err != nil {
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Invalid HTTP request: " + err.Error()}},
		}, nil
	}

	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	match := s.engine.InspectHTTPRequest(httpReq, []byte(bodyStr))
	if match.Blocked {
		atomic.AddUint64(&s.stats.TotalBlocked, 1)
		slog.Warn("outbound request blocked by snort rule",
			"url", rawURL,
			"method", method,
			"sid", match.MatchedRule.SID,
			"reason", match.Reason,
		)
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf("SECURITY VIOLATION: Outbound request blocked by policy. Reason: %s (Action: %s)",
					match.Reason, match.Action),
			}},
		}, nil
	}

	atomic.AddUint64(&s.stats.TotalPassed, 1)

	// 2. Execute the request safely
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(reqCtx)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Request failed: " + err.Error()}},
		}, nil
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes))
	if err != nil {
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Reading response body failed: " + err.Error()}},
		}, nil
	}

	// Format response output
	outHeaders := make(map[string]string)
	for k, v := range resp.Header {
		outHeaders[k] = strings.Join(v, ", ")
	}

	summary := map[string]any{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
		"headers":     outHeaders,
		"body":        string(respBytes),
	}
	encoded, _ := json.MarshalIndent(summary, "", "  ")

	return &ToolCallResult{
		IsError: resp.StatusCode >= 400,
		Content: []ToolContent{{
			Type: "text",
			Text: string(encoded),
		}},
	}, nil
}

func (s *Server) executeCheckPayload(args map[string]any) (*ToolCallResult, *JSONRPCError) {
	rawURL, _ := args["url"].(string)
	method := "GET"
	if m, ok := args["method"].(string); ok && m != "" {
		method = strings.ToUpper(m)
	}
	bodyStr, _ := args["body"].(string)

	headers := make(map[string]string)
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			if vs, ok := v.(string); ok {
				headers[k] = vs
			}
		}
	}

	httpReq, err := http.NewRequest(method, rawURL, strings.NewReader(bodyStr))
	if err != nil {
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Invalid URL or request parameters: " + err.Error()}},
		}, nil
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	match := s.engine.InspectHTTPRequest(httpReq, []byte(bodyStr))
	res := map[string]any{
		"blocked": match.Blocked,
		"matched": match.Matched,
	}
	if match.MatchedRule != nil {
		res["rule_sid"] = match.MatchedRule.SID
		res["rule_msg"] = match.MatchedRule.Message
		res["classtype"] = match.MatchedRule.ClassType
		res["action"] = string(match.Action)
	}

	encoded, _ := json.MarshalIndent(res, "", "  ")
	return &ToolCallResult{
		Content: []ToolContent{{Type: "text", Text: string(encoded)}},
	}, nil
}

func (s *Server) executeGetStats() (*ToolCallResult, *JSONRPCError) {
	stats := map[string]any{
		"total_inspected": atomic.LoadUint64(&s.stats.TotalInspected),
		"total_passed":    atomic.LoadUint64(&s.stats.TotalPassed),
		"total_blocked":   atomic.LoadUint64(&s.stats.TotalBlocked),
		"rules_loaded":    s.engine.RuleCount(),
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
			"description": "Proxies outbound HTTP/API requests with Snort-based intrusion detection and exploit protection. Replaces raw curl, socket, or python HTTP calls to 3rd-party servers.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "The destination URL to request (e.g. https://api.anthropic.com/v1/messages or https://api.github.com/repos)",
					},
					"method": map[string]any{
						"type":        "string",
						"description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD)",
						"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"},
						"default":     "GET",
					},
					"headers": map[string]any{
						"type":                 "object",
						"description":          "HTTP headers as key-value pairs (e.g. Authorization, Content-Type)",
						"additionalProperties": map[string]any{"type": "string"},
					},
					"body": map[string]any{
						"type":        "string",
						"description": "Request body payload for POST/PUT/PATCH requests",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds (default: 30)",
						"default":     30,
					},
				},
				"required": []string{"url"},
			},
		},
		{
			"name":        "check_security_payload",
			"description": "Pre-flight diagnostic tool to inspect whether a URL, headers, or body violates Snort security rules without sending network traffic.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "URL to inspect",
					},
					"method": map[string]any{
						"type":    "string",
						"default": "GET",
					},
					"headers": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string"},
					},
					"body": map[string]any{
						"type": "string",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			"name":        "get_security_stats",
			"description": "Returns operational statistics on requests inspected, passed, and blocked by Snort rules.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}
