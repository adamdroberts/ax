package egress

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/ax/pkg/security/httpguard"
)

// checkConditions rejects contradictions that can be established from the
// request and returned representation metadata. Missing validators are unknown,
// and a mutation's response validators describe its post-write representation.
func (m *responseMetadata) checkConditions(status int, req *http.Request) error {
	if req == nil {
		return nil
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if err := httpguard.ValidateConditionalRequest(method, req.Header); err != nil {
		return err
	}
	conditions := map[string]string{}
	for name, values := range req.Header {
		switch key := strings.ToLower(name); key {
		case "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range":
			conditions[key] = strings.Trim(values[0], " ")
		}
	}
	read := method == "GET" || method == "HEAD"
	if status == 304 && (!read || conditions["if-none-match"] == "" && conditions["if-modified-since"] == "") {
		return fmt.Errorf("304 requires a conditional GET or HEAD request")
	}
	// Redirects and errors take precedence over conditional evaluation. Other
	// methods can legitimately return new validators after applying a write.
	if !read || status != 200 && status != 206 && status != 304 {
		return nil
	}
	if value := conditions["if-match"]; value != "" {
		if value != "*" && m.etag != "" {
			match, err := httpguard.MatchEntityTagList(value, m.etag, true)
			if err != nil {
				return err
			}
			if !match {
				return fmt.Errorf("response contradicts If-Match")
			}
		}
	} else if value := conditions["if-unmodified-since"]; value != "" && m.lastModified != "" {
		key, err := httpguard.HTTPDateOrderKey(value, false)
		if err != nil {
			return err
		}
		if m.lastModified > key {
			return fmt.Errorf("response contradicts If-Unmodified-Since")
		}
	}
	if value := conditions["if-none-match"]; value != "" {
		known, match := value == "*", value == "*"
		if !known && m.etag != "" {
			var err error
			match, err = httpguard.MatchEntityTagList(value, m.etag, false)
			if err != nil {
				return err
			}
			known = true
		}
		if known && match != (status == 304) {
			return fmt.Errorf("response contradicts If-None-Match")
		}
	} else if value := conditions["if-modified-since"]; value != "" && status == 304 && m.lastModified != "" {
		key, err := httpguard.HTTPDateOrderKey(value, false)
		if err != nil {
			return err
		}
		if m.lastModified > key {
			return fmt.Errorf("304 contradicts If-Modified-Since")
		}
		// If-Modified-Since evaluation is a SHOULD: a 200/206 response with an
		// older Last-Modified value alone does not establish a contradiction.
	}
	if value := conditions["if-range"]; status == 206 && value != "" {
		if strings.HasPrefix(value, "\"") {
			if m.etag != "" && value != m.etag {
				return fmt.Errorf("partial response contradicts If-Range entity tag")
			}
		} else if m.lastModified != "" {
			key, err := httpguard.HTTPDateOrderKey(value, false)
			if err != nil {
				return err
			}
			if m.lastModified != key {
				return fmt.Errorf("partial response contradicts If-Range date")
			}
		}
	}
	return nil
}
