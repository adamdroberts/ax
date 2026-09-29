package httpguard

import (
	"fmt"
	"net/http"
	"strings"
)

// ContentRange is the bytes-only Content-Range profile (RFC 9110 section 14.4).
// CompleteKnown distinguishes an unknown length from an empty representation.
// Size uses uint64 so a 0..MaxInt64 interval cannot wrap into a negative length.
type ContentRange struct {
	First, Last, Complete, Size uint64
	CompleteKnown, Unsatisfied  bool
}

func ParseContentRange(value string) (*ContentRange, error) {
	invalid := func() (*ContentRange, error) { return nil, fmt.Errorf("invalid or unsupported Content-Range") }
	if len(value) > 8192 {
		return invalid()
	}
	unit, value, space := strings.Cut(value, " ")
	interval, complete, slash := strings.Cut(value, "/")
	if !space || !strings.EqualFold(unit, "bytes") || !slash {
		return invalid()
	}
	r := &ContentRange{CompleteKnown: complete != "*", Unsatisfied: interval == "*"}
	var ok bool
	if r.CompleteKnown {
		if r.Complete, ok = rangeNumber(complete); !ok {
			return invalid()
		}
	}
	if r.Unsatisfied {
		if !r.CompleteKnown {
			return invalid()
		}
		return r, nil
	}
	first, last, dash := strings.Cut(interval, "-")
	if !dash {
		return invalid()
	}
	if r.First, ok = rangeNumber(first); !ok {
		return invalid()
	}
	if r.Last, ok = rangeNumber(last); !ok || r.Last < r.First || r.CompleteKnown && r.Complete <= r.Last {
		return invalid()
	}
	r.Size = r.Last - r.First + 1
	return r, nil
}

// ValidateContentRangeRequest restricts partial uploads to one fulfilled byte
// range on PUT. The caller supplies the known content byte length. MCP admission
// uses the actual UTF-8 body; the transport also checks its declared length.
// Supporting partial PUT at an origin still requires an application agreement.
func ValidateContentRangeRequest(method string, headers http.Header, bodyBytes int64) error {
	seen := false
	for name, values := range headers {
		if !strings.EqualFold(name, "Content-Range") {
			continue
		}
		if seen || len(values) != 1 || method != "PUT" {
			return fmt.Errorf("partial uploads require PUT and one Content-Range field")
		}
		seen = true
		r, err := ParseContentRange(values[0])
		if err != nil {
			return err
		}
		if r.Unsatisfied || bodyBytes < 0 || uint64(bodyBytes) != r.Size {
			return fmt.Errorf("partial upload Content-Range disagrees with body length")
		}
	}
	return nil
}
