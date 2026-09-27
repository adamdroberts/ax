package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/ax/pkg/security/httpguard"
)

// decodeRequest validates before Go's decoder can replace invalid Unicode or
// collapse duplicate fields. The broker implements individual MCP requests,
// not JSON-RPC batches or arbitrary JSON-RPC parameter shapes.
func decodeRequest(line []byte, req *JSONRPCRequest) error {
	if len(line) > 8*1024*1024 {
		return fmt.Errorf("RPC message limit")
	}
	if err := httpguard.ValidateJSON(line); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil || fields == nil {
		return fmt.Errorf("RPC must be an object")
	}
	for name := range fields {
		if name != "jsonrpc" && name != "id" && name != "method" && name != "params" {
			return fmt.Errorf("unknown RPC property")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(req); err != nil {
		return fmt.Errorf("invalid RPC fields")
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return fmt.Errorf("invalid RPC version or method")
	}
	if params, exists := fields["params"]; exists && (len(params) == 0 || params[0] != '{') {
		return fmt.Errorf("MCP params must be an object")
	}
	if _, exists := fields["id"]; !exists {
		if req.Method != "notifications/initialized" {
			return fmt.Errorf("MCP requests require an ID")
		}
		return nil
	}
	switch id := req.ID.(type) {
	case string:
	case json.Number:
		n, err := strconv.ParseInt(string(id), 10, 64)
		if err != nil || n < -9007199254740991 || n > 9007199254740991 {
			return fmt.Errorf("RPC ID must be an interoperable integer")
		}
	default:
		return fmt.Errorf("RPC ID must be a string or integer")
	}
	if req.Method == "notifications/initialized" {
		return fmt.Errorf("initialized notification cannot have an ID")
	}
	return nil
}
