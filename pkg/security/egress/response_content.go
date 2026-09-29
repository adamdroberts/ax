package egress

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/ax/pkg/security/httpguard"
)

// CheckResponseBody applies the broker's JSON/XML contracts to a complete response
// after framing, size and UTF-8 checks. It preserves the original bytes. A 206
// single range is checked when its metadata establishes a complete document;
// complete multipart representations are checked by the range body guard.
// Other media are not sniffed or interpreted. This does not establish trust.
func CheckResponseBody(resp *http.Response, method string, body []byte) error {
	if resp == nil || len(body) > MaxResponseBodyBytes {
		return fmt.Errorf("invalid or oversized response body")
	}
	if err := httpguard.ValidateLocationHeaders(resp.Header, true); err != nil {
		return err
	}
	if err := httpguard.ValidateDigestPreferences(resp.Header); err != nil {
		return err
	}
	// Content-Digest covers actual HTTP content, including a single fragment or
	// an entire multipart envelope, independently of representation selection.
	if err := checkResponseContentDigest(resp, body); err != nil {
		return err
	}
	if err := checkResponseRepresentationDigest(resp, method, body); err != nil {
		return err
	}
	kind, seen := "", false
	for name, values := range resp.Header {
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		if seen || len(values) != 1 {
			return fmt.Errorf("ambiguous response Content-Type")
		}
		seen = true
		var err error
		kind, _, err = parseResponseContentType(values[0])
		if err != nil {
			return err
		}
	}
	if method == "HEAD" || resp.StatusCode == 204 || resp.StatusCode == 205 || resp.StatusCode == 304 {
		if len(body) != 0 {
			return fmt.Errorf("content on a bodyless response")
		}
		return nil
	}
	if !isJSONMediaType(kind) && !isXMLMediaType(kind) {
		return nil
	}
	if resp.StatusCode == 206 {
		var interval *httpguard.ContentRange
		for name, values := range resp.Header {
			if !strings.EqualFold(name, "Content-Range") {
				continue
			}
			if interval != nil || len(values) != 1 {
				return fmt.Errorf("ambiguous structured response Content-Range")
			}
			var err error
			interval, err = httpguard.ParseContentRange(strings.Trim(values[0], " "))
			if err != nil {
				return err
			}
		}
		if interval == nil || interval.Unsatisfied || interval.Size != uint64(len(body)) {
			return fmt.Errorf("invalid structured response range or body length")
		}
		if !interval.CompleteKnown || interval.First != 0 || interval.Size != interval.Complete {
			return nil // An incomplete fragment is not a complete document.
		}
	}
	if isXMLMediaType(kind) {
		return checkResponseXML(body)
	}
	return checkResponseJSON(body)
}

func isXMLMediaType(kind string) bool {
	return kind == "application/xml" || kind == "text/xml" || strings.HasSuffix(kind, "+xml")
}

func isJSONMediaType(kind string) bool {
	return kind == "application/json" || strings.HasSuffix(kind, "+json")
}

func checkResponseJSON(body []byte) error {
	if err := httpguard.ValidateJSON(body); err != nil {
		return fmt.Errorf("response violates the JSON interoperability policy")
	}
	return nil
}
