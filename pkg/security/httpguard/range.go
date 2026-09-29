package httpguard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const MaxRangeMembers = 16

// ByteRange is a parsed request interval. For a suffix, Last is the suffix
// length; for an open interval Last is unspecified. ParseByteRanges validates
// the bounded request profile before returning these values.
type ByteRange struct {
	First, Last       uint64
	OpenEnded, Suffix bool
}

// validateByteRange checks RFC 9110 section 14 grammar plus a bounded local
// profile: bytes only, signed 63-bit values, ascending disjoint intervals and
// a suffix only on its own. Resource length and satisfiability are not inferred.
func validateByteRange(value string) error {
	_, err := ParseByteRanges(value)
	return err
}

func ParseByteRanges(value string) ([]ByteRange, error) {
	if len(value) > 8192 {
		return nil, fmt.Errorf("range field exceeds limit")
	}
	unit, remaining, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(unit, "bytes") {
		return nil, fmt.Errorf("only byte range requests are supported")
	}
	var ranges []ByteRange
	var previousEnd uint64
	var open, suffix bool
	for slots := 1; ; slots++ {
		if slots > MaxRangeMembers {
			return nil, fmt.Errorf("range request exceeds member limit")
		}
		member, rest, more := strings.Cut(remaining, ",")
		member = strings.Trim(member, " ")
		// RFC 9110's list grammar tolerates a bounded number of empty slots.
		if member != "" {
			r := ByteRange{}
			first, last, dash := strings.Cut(member, "-")
			if !dash || open || suffix {
				return nil, fmt.Errorf("invalid or overlapping byte range request")
			}
			if first == "" {
				length, ok := rangeNumber(last)
				if !ok || len(ranges) != 0 {
					return nil, fmt.Errorf("suffix byte range must be valid and stand alone")
				}
				suffix = true
				r.Suffix, r.Last = true, length
			} else {
				start, ok := rangeNumber(first)
				if !ok || len(ranges) != 0 && start <= previousEnd {
					return nil, fmt.Errorf("byte ranges must be valid, ascending and disjoint")
				}
				r.First = start
				if last == "" {
					open = true
					r.OpenEnded = true
				} else {
					end, ok := rangeNumber(last)
					if !ok || end < start {
						return nil, fmt.Errorf("invalid byte range endpoints")
					}
					previousEnd = end
					r.Last = end
				}
			}
			ranges = append(ranges, r)
		}
		if !more {
			if len(ranges) == 0 {
				return nil, fmt.Errorf("range request must contain a range")
			}
			return ranges, nil
		}
		remaining = rest
	}
}

// ValidateReturnedRange applies the broker's bounds contract to a fulfilled
// Content-Range and parsed request ranges. It permits subsets and coalescing:
// each returned endpoint must fall within a requested interval. No hypothetical
// multipart overhead is inferred to impose a gap-size threshold. A nil request
// means the caller has no request context, not an empty Range field.
func ValidateReturnedRange(requested []ByteRange, returned *ContentRange) error {
	if requested == nil {
		return nil
	}
	bad := func() error { return fmt.Errorf("response range lies outside requested bounds") }
	if returned == nil || returned.Unsatisfied {
		return bad()
	}
	starts, ends := false, false
	for _, r := range requested {
		first, last := r.First, r.Last
		if r.Suffix {
			if r.Last == 0 {
				return bad()
			}
			if !returned.CompleteKnown {
				// Without a total, only the maximum possible suffix size can
				// be checked; choosing an absolute suffix origin would invent it.
				if returned.Size <= r.Last {
					return nil
				}
				return bad()
			}
			first = 0
			if returned.Complete > r.Last {
				first = returned.Complete - r.Last
			}
			last = returned.Complete - 1 // Fulfilled ranges have a nonzero total.
		} else {
			if r.OpenEnded {
				last = 1<<63 - 1
			}
			if returned.CompleteKnown {
				if first >= returned.Complete {
					continue // This requested member is unsatisfiable.
				}
				last = min(last, returned.Complete-1)
			}
		}
		starts = starts || first <= returned.First && returned.First <= last
		ends = ends || first <= returned.Last && returned.Last <= last
	}
	if !starts || !ends {
		return bad()
	}
	return nil
}

func rangeNumber(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for _, c := range []byte(value) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	// Leading zeroes are valid decimal syntax, never an octal indicator. The
	// broker's numeric ceiling is policy, not an RFC limit on resource size.
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(value, 10, 63)
	return n, err == nil
}

// ValidateRangeRequest also protects callers of the Go transport directly.
// The MCP header map cannot express repeated values; http.Header can.
func ValidateRangeRequest(method string, headers http.Header) error {
	seen := false
	for name, values := range headers {
		if !strings.EqualFold(name, "Range") {
			continue
		}
		if seen || len(values) != 1 || method != "GET" {
			return fmt.Errorf("range requests require GET and one Range field")
		}
		seen = true
		if err := ValidateHeader(name, values[0]); err != nil {
			return err
		}
	}
	return nil
}
