package egress

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/ax/pkg/security/httpguard"
)

type partialResponse struct {
	size           uint64
	boundary       string
	requested      []httpguard.ByteRange
	representation *contentDigests
}

type multipartRangePart struct {
	interval httpguard.ContentRange
	content  []byte
}

func responseRanges(req *http.Request) ([]httpguard.ByteRange, error) {
	if req == nil {
		return nil, nil // Wire validation has no request-field context yet.
	}
	if err := httpguard.ValidateRangeRequest(req.Method, req.Header); err != nil {
		return nil, err
	}
	for name, values := range req.Header {
		if strings.EqualFold(name, "Range") {
			return httpguard.ParseByteRanges(values[0])
		}
	}
	return []httpguard.ByteRange{}, nil // Known request without a Range field.
}

func (m *responseMetadata) partial(status int, method string, length int64, requested []httpguard.ByteRange) (*partialResponse, error) {
	r := m.contentRange
	if status != http.StatusPartialContent {
		if r != nil && (status != http.StatusRequestedRangeNotSatisfiable || !r.Unsatisfied) {
			return nil, fmt.Errorf("Content-Range is inconsistent with response status")
		}
		return nil, nil
	}
	if method != "" && method != "GET" || requested != nil && len(requested) == 0 {
		return nil, fmt.Errorf("partial response requires a GET range request")
	}
	if m.mediaType == "multipart/byteranges" {
		boundary := m.mediaParameters["boundary"]
		if r != nil || len(requested) == 1 || !validRangeBoundary(boundary) {
			return nil, fmt.Errorf("invalid multipart range response metadata")
		}
		return &partialResponse{boundary: boundary, requested: requested}, nil
	}
	if r == nil || r.Unsatisfied || r.Size > MaxResponseBodyBytes || length >= 0 && uint64(length) != r.Size {
		return nil, fmt.Errorf("partial response Content-Range disagrees with body length")
	}
	if err := httpguard.ValidateReturnedRange(requested, r); err != nil {
		return nil, err
	}
	return &partialResponse{size: r.Size, requested: requested}, nil
}

func validRangeBoundary(value string) bool {
	if len(value) < 1 || len(value) > 70 || value[len(value)-1] == ' ' {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("'()+_,-./:=? ", rune(c))) {
			return false
		}
	}
	return true
}

// checkMultipartRanges validates the original content without a MIME reader's
// header unfolding, transfer decoding or newline repair. The response body is
// already bounded and dechunked. Valid content is returned to MCP unchanged.
// Complete JSON is assembled only for validation within this one response;
// neither ranges nor validators prove origin resource ownership.
func checkMultipartRanges(body []byte, boundary string) error {
	return checkMultipartRangesForRequest(body, boundary, nil)
}

func checkMultipartRangesForRequest(body []byte, boundary string, requested []httpguard.ByteRange) error {
	return checkMultipartRangesForRequestAndDigest(body, boundary, requested, nil)
}

func checkMultipartRangesForRequestAndDigest(body []byte, boundary string, requested []httpguard.ByteRange, representation *contentDigests) error {
	bad := func() error { return fmt.Errorf("invalid or inconsistent multipart byte ranges") }
	if len(body) > MaxResponseBodyBytes {
		return bad()
	}
	marker := []byte("--" + boundary)
	position := 0
	if !bytes.HasPrefix(body, marker) {
		position = bytes.Index(body, append([]byte("\r\n"), marker...))
		if position < 0 {
			return bad()
		}
		position += 2 // RFC 2046 preamble is not part of the first body part.
	}
	parts, headerBytes, headerCount := 0, 0, 0
	var complete, greatestLast uint64
	completeKnown := false
	jsonRepresentation, xmlRepresentation := false, false
	var returned []multipartRangePart
	for {
		if !bytes.HasPrefix(body[position:], marker) {
			return bad()
		}
		position += len(marker)
		closing := bytes.HasPrefix(body[position:], []byte("--"))
		if closing {
			position += 2
		}
		lineEnd := bytes.Index(body[position:], []byte("\r\n"))
		if lineEnd < 0 {
			if !closing {
				return bad()
			}
			lineEnd = len(body) - position
		}
		if lineEnd > 8192 || len(bytes.Trim(body[position:position+lineEnd], " \t")) != 0 {
			return bad()
		}
		if closing {
			if parts == 0 {
				return bad()
			}
			for _, part := range returned {
				r := part.interval
				if completeKnown && !r.CompleteKnown {
					r.Complete, r.CompleteKnown = complete, true
				}
				if err := httpguard.ValidateReturnedRange(requested, &r); err != nil {
					return err
				}
			}
			if representation != nil && !completeKnown {
				return representationUnavailable()
			}
			if (jsonRepresentation || xmlRepresentation || representation != nil) && completeKnown {
				return checkCompleteMultipartContentAndDigest(returned, complete, jsonRepresentation, xmlRepresentation, representation)
			}
			return nil // A final CRLF and epilogue are optional.
		}
		position += lineEnd + 2
		parts++
		if parts > httpguard.MaxRangeMembers {
			return bad()
		}
		metadata := responseMetadata{mimePart: true}
		identityFields := map[string]bool{}
		for {
			lineEnd = bytes.Index(body[position:], []byte("\r\n"))
			if lineEnd < 0 || lineEnd+2 > 8192 || headerBytes+lineEnd+2 > MaxResponseHeaderBytes {
				return bad()
			}
			line := body[position : position+lineEnd]
			position += lineEnd + 2
			headerBytes += lineEnd + 2
			if len(line) == 0 {
				break
			}
			headerCount++
			if headerCount > MaxResponseHeaders || bytes.HasPrefix(line, marker) {
				return bad()
			}
			name, value, colon := strings.Cut(string(line), ":")
			if !colon || !headerToken(name) {
				return bad()
			}
			for _, c := range []byte(value) {
				if c < 32 || c > 126 {
					return bad()
				}
			}
			name, value = strings.ToLower(name), strings.Trim(value, " ")
			if err := metadata.add(name, value); err != nil {
				return err
			}
			switch name {
			case "content-transfer-encoding", "content-encoding":
				// Binary/identity preserve Content-Range's octet interpretation.
				want := "binary"
				if name == "content-encoding" {
					want = "identity"
				}
				if identityFields[name] || !strings.EqualFold(value, want) {
					return bad()
				}
				identityFields[name] = true
			case "content-length", "transfer-encoding", "trailer", "connection", "upgrade":
				return bad() // Part framing is exclusively its MIME boundary.
			}
		}
		jsonRepresentation = jsonRepresentation || isJSONMediaType(metadata.mediaType)
		xmlRepresentation = xmlRepresentation || isXMLMediaType(metadata.mediaType)
		r := metadata.contentRange
		if r == nil || r.Unsatisfied || r.Size > uint64(len(body)-position) {
			return bad()
		}
		if r.CompleteKnown {
			if completeKnown && complete != r.Complete {
				return bad()
			}
			complete, completeKnown = r.Complete, true
		}
		if r.Last > greatestLast {
			greatestLast = r.Last
		}
		if completeKnown && greatestLast >= complete {
			return bad()
		}
		end := position + int(r.Size) // Size is bounded by the available body.
		part := body[position:end]
		if bytes.HasPrefix(part, marker) || bytes.Contains(part, append([]byte("\r\n"), marker...)) || !bytes.HasPrefix(body[end:], []byte("\r\n")) {
			return bad()
		}
		// Parts describe the same representation. Keep views into the bounded
		// body and compare relative offsets; never allocate by resource position.
		// At most 16 parts bounds pairwise work even for repeated large overlaps.
		for _, previous := range returned {
			first := max(r.First, previous.interval.First)
			last := min(r.Last, previous.interval.Last)
			if first > last {
				continue
			}
			start, otherStart, size := first-r.First, first-previous.interval.First, last-first+1
			if !bytes.Equal(part[start:start+size], previous.content[otherStart:otherStart+size]) {
				return fmt.Errorf("conflicting multipart byte ranges")
			}
		}
		returned = append(returned, multipartRangePart{interval: *r, content: part})
		position = end + 2
	}
}

// Ranges in one multipart response describe one selected representation. If
// any part declares JSON or XML, apply each selected contract when all bytes are available.
// First prove continuous coverage within the body budget, then allocate: an
// attacker-selected large total or offset must never size an allocation.
func checkCompleteMultipartContent(parts []multipartRangePart, complete uint64, jsonRepresentation, xmlRepresentation bool) error {
	return checkCompleteMultipartContentAndDigest(parts, complete, jsonRepresentation, xmlRepresentation, nil)
}

func checkCompleteMultipartContentAndDigest(parts []multipartRangePart, complete uint64, jsonRepresentation, xmlRepresentation bool, representation *contentDigests) error {
	incomplete := func() error {
		if representation != nil {
			return representationUnavailable()
		}
		return nil
	}
	if complete > MaxResponseBodyBytes {
		return incomplete()
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].interval.First < parts[j].interval.First })
	var covered uint64
	for _, part := range parts {
		if part.interval.First > covered {
			return incomplete()
		}
		covered = max(covered, part.interval.Last+1)
	}
	if covered != complete {
		return incomplete()
	}
	document := make([]byte, int(complete))
	for _, part := range parts {
		copy(document[part.interval.First:], part.content)
	}
	if representation != nil {
		if err := representation.CheckBody(document); err != nil {
			return err
		}
	}
	if jsonRepresentation {
		if err := checkResponseJSON(document); err != nil {
			return err
		}
	}
	if xmlRepresentation {
		return checkResponseXML(document)
	}
	return nil
}
