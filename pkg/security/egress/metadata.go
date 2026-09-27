// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"fmt"
	"strings"
)

const MaxResponseMetadataParts = 128

var responseSingletons = headerSet(`content-length transfer-encoding content-encoding content-type
content-location content-range date etag last-modified location retry-after server`)

var protectedConnectionNames = headerSet(`host content-length transfer-encoding connection upgrade trailer te
expect http2-settings forwarded x-original-url x-rewrite-url x-http-method-override x-method-override
x-http-method x-host origin referer content-transfer-encoding x-original-host x-real-ip x-agent-id
x-approval-token content-type content-encoding content-language content-location content-range
content-disposition authorization proxy-authorization www-authenticate proxy-authenticate authentication-info
proxy-authentication-info cookie set-cookie location date age expires retry-after server etag last-modified
cache-control vary warning allow accept-ranges range if-match if-none-match if-modified-since
if-unmodified-since if-range`)

var protectedConnectionPrefixes = []string{"proxy-", "sec-", "x-forwarded"}

func headerSet(names string) map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Fields(names) {
		set[name] = true
	}
	return set
}

// responseMetadata validates one header block. This is an explicit field
// contract, not a claim that all registered or extension fields are singletons.
type responseMetadata struct {
	seen            map[string]bool
	connectionParts int
}

func (m *responseMetadata) add(name, value string) error {
	name = strings.ToLower(name)
	if responseSingletons[name] {
		if m.seen[name] {
			return fmt.Errorf("duplicate singleton response field")
		}
		if m.seen == nil {
			m.seen = make(map[string]bool)
		}
		m.seen[name] = true
	}
	if name == "content-type" {
		return checkResponseContentType(value)
	}
	if name != "connection" {
		return nil
	}
	for {
		member, rest, more := strings.Cut(value, ",")
		m.connectionParts++
		if m.connectionParts > MaxResponseMetadataParts {
			return fmt.Errorf("too many response connection options")
		}
		member = strings.ToLower(strings.Trim(member, " "))
		// RFC 9110 recipients tolerate a bounded number of empty list members.
		if member != "" {
			if !headerToken(member) {
				return fmt.Errorf("invalid response connection option")
			}
			protected := protectedConnectionNames[member]
			for _, prefix := range protectedConnectionPrefixes {
				protected = protected || strings.HasPrefix(member, prefix)
			}
			if protected {
				return fmt.Errorf("response connection option nominates protected metadata")
			}
		}
		if !more {
			return nil
		}
		value = rest
	}
}

// Parse the original field before a MIME library can merge duplicate parameters
// or apply RFC 2231/8187 continuations. Only an explicitly named UTF-8 charset
// is supported; media types and other ordinary parameters remain extensible.
func checkResponseContentType(value string) error {
	if len(value) > 8192 {
		return fmt.Errorf("response media type exceeds field limit")
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return fmt.Errorf("invalid response media type bytes")
		}
	}
	value = strings.Trim(value, " ")
	i := 0
	readToken := func() string {
		start := i
		for i < len(value) && tokenByte(value[i]) {
			i++
		}
		return value[start:i]
	}
	if readToken() == "" || i == len(value) || value[i] != '/' {
		return fmt.Errorf("invalid response media type")
	}
	i++
	if readToken() == "" {
		return fmt.Errorf("invalid response media subtype")
	}
	seen := map[string]bool{}
	parts := 0
	for i < len(value) {
		for i < len(value) && value[i] == ' ' {
			i++
		}
		if i == len(value) {
			break
		}
		if value[i] != ';' {
			return fmt.Errorf("invalid response media parameter separator")
		}
		i++
		parts++
		if parts > MaxResponseMetadataParts {
			return fmt.Errorf("too many response media parameters")
		}
		for i < len(value) && value[i] == ' ' {
			i++
		}
		if i == len(value) || value[i] == ';' {
			continue // Empty parameter slots are permitted by RFC 9110's grammar.
		}
		name := strings.ToLower(readToken())
		if name == "" || strings.Contains(name, "*") || seen[name] || i == len(value) || value[i] != '=' {
			return fmt.Errorf("invalid or duplicate response media parameter")
		}
		seen[name] = true
		i++
		var parameter string
		if i < len(value) && value[i] == '"' {
			i++
			var decoded strings.Builder
			closed := false
			for i < len(value) {
				c := value[i]
				i++
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' {
					if i == len(value) {
						return fmt.Errorf("truncated response media escape")
					}
					c = value[i]
					i++
				}
				decoded.WriteByte(c)
			}
			if !closed {
				return fmt.Errorf("unterminated response media string")
			}
			parameter = decoded.String()
		} else {
			parameter = readToken()
			if parameter == "" {
				return fmt.Errorf("empty response media parameter")
			}
		}
		if name == "charset" && !strings.EqualFold(parameter, "utf-8") {
			return fmt.Errorf("unsupported response charset")
		}
	}
	return nil
}
