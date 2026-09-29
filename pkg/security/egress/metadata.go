// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"fmt"
	"strings"

	"github.com/google/ax/pkg/security/httpguard"
)

const MaxResponseMetadataParts = 128

var responseSingletons = headerSet(`content-length transfer-encoding content-encoding content-type
content-location content-range content-disposition date etag last-modified location retry-after server`)

var protectedConnectionNames = headerSet(`host content-length transfer-encoding connection upgrade trailer te
expect http2-settings forwarded x-original-url x-rewrite-url x-http-method-override x-method-override
x-http-method x-host origin referer content-transfer-encoding x-original-host x-real-ip x-agent-id
x-approval-token content-type content-encoding content-language content-location content-range
content-disposition content-digest repr-digest want-content-digest want-repr-digest authorization proxy-authorization www-authenticate proxy-authenticate authentication-info
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
	mimePart                 bool
	seen                     map[string]bool
	connectionParts          int
	contentRange             *httpguard.ContentRange
	mediaType                string
	mediaParameters          map[string]string
	etag                     string
	date                     string
	lastModified             string
	contentDigest            contentDigests
	representationDigest     contentDigests
	emptyRepresentation      bool
	wantContentDigest        httpguard.DigestPreferences
	wantRepresentationDigest httpguard.DigestPreferences
}

func (m *responseMetadata) add(name, value string) error {
	name = strings.ToLower(name)
	if name == "want-content-digest" || name == "want-repr-digest" {
		if m.mimePart {
			return nil
		}
		if name == "want-content-digest" {
			return m.wantContentDigest.Add(value)
		}
		return m.wantRepresentationDigest.Add(value)
	}
	if name == "content-digest" {
		if m.mimePart {
			return nil
		} // HTTP message integrity is separate from MIME part metadata.
		return m.contentDigest.Add(value)
	}
	if name == "repr-digest" {
		if m.mimePart {
			return nil
		}
		return m.representationDigest.Add(value)
	}
	if name == "content-length" {
		m.emptyRepresentation = value == "0"
	}
	if name == "content-disposition" && m.mimePart {
		return nil // RFC 6266 does not govern fields inside MIME payloads.
	}
	if responseSingletons[name] {
		if m.seen[name] {
			return fmt.Errorf("duplicate singleton response field")
		}
		if m.seen == nil {
			m.seen = make(map[string]bool)
		}
		m.seen[name] = true
	}
	if name == "content-disposition" {
		return checkResponseDisposition(value)
	}
	if (name == "location" || name == "content-location") && !m.mimePart {
		return httpguard.ValidateURIReference(value, name == "location")
	}
	if name == "content-type" {
		var err error
		m.mediaType, m.mediaParameters, err = parseResponseContentType(value)
		return err
	}
	if name == "content-range" {
		var err error
		m.contentRange, err = httpguard.ParseContentRange(value)
		return err
	}
	if name == "etag" {
		_, err := httpguard.ValidateEntityTag(value)
		if err == nil {
			m.etag = value
		}
		return err
	}
	if name == "date" || name == "last-modified" {
		key, err := httpguard.HTTPDateOrderKey(value, true)
		if err != nil {
			return err
		}
		if name == "date" {
			m.date = key
		} else {
			m.lastModified = key
		}
		if m.date != "" && m.lastModified > m.date {
			return fmt.Errorf("Last-Modified is later than response Date")
		}
		return nil
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

func (m *responseMetadata) finish(status int, method string) error {
	if err := m.finishRepresentation(status, method); err != nil {
		return err
	}
	if err := m.contentDigest.Ready(); err != nil {
		return err
	}
	if status < 200 || method == "HEAD" || status == 204 || status == 205 || status == 304 {
		return m.contentDigest.CheckBody(nil)
	}
	return nil
}

// Parse the original field before a MIME library can merge duplicate parameters
// or apply RFC 2231/8187 continuations. Only an explicitly named UTF-8 charset
// is supported; media types and other ordinary parameters remain extensible.
func checkResponseContentType(value string) error {
	_, _, err := parseResponseContentType(value)
	return err
}

func parseResponseContentType(value string) (string, map[string]string, error) {
	if len(value) > 8192 {
		return "", nil, fmt.Errorf("response media type exceeds field limit")
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return "", nil, fmt.Errorf("invalid response media type bytes")
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
		return "", nil, fmt.Errorf("invalid response media type")
	}
	i++
	if readToken() == "" {
		return "", nil, fmt.Errorf("invalid response media subtype")
	}
	kind := strings.ToLower(value[:i])
	parameters := map[string]string{}
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
			return "", nil, fmt.Errorf("invalid response media parameter separator")
		}
		i++
		parts++
		if parts > MaxResponseMetadataParts {
			return "", nil, fmt.Errorf("too many response media parameters")
		}
		for i < len(value) && value[i] == ' ' {
			i++
		}
		if i == len(value) || value[i] == ';' {
			continue // Empty parameter slots are permitted by RFC 9110's grammar.
		}
		name := strings.ToLower(readToken())
		if name == "" || strings.Contains(name, "*") || seen[name] || i == len(value) || value[i] != '=' {
			return "", nil, fmt.Errorf("invalid or duplicate response media parameter")
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
						return "", nil, fmt.Errorf("truncated response media escape")
					}
					c = value[i]
					i++
				}
				decoded.WriteByte(c)
			}
			if !closed {
				return "", nil, fmt.Errorf("unterminated response media string")
			}
			parameter = decoded.String()
		} else {
			parameter = readToken()
			if parameter == "" {
				return "", nil, fmt.Errorf("empty response media parameter")
			}
		}
		if name == "charset" && !strings.EqualFold(parameter, "utf-8") {
			return "", nil, fmt.Errorf("unsupported response charset")
		}
		parameters[name] = parameter
	}
	return kind, parameters, nil
}
