package egress

import (
	"fmt"
	"net/http"
	"strings"
)

func representationUnavailable() error {
	return fmt.Errorf("representation digest requires complete representation data")
}

// Repr-Digest is representation metadata. HEAD/304 do not expose those bytes;
// only an explicit zero representation length establishes an empty resource.
// 204/205 can describe a post-write resource without conveying its bytes.
// These uncheckable cases are denied by local policy, not declared RFC errors.
func (m *responseMetadata) finishRepresentation(status int, method string) error {
	d := &m.representationDigest
	if err := d.Ready(); err != nil {
		return err
	}
	if !d.Present() {
		return nil
	}
	if status < 200 {
		return d.CheckBody(nil)
	}
	if status == 204 || status == 205 {
		return representationUnavailable()
	}
	if method == "HEAD" || status == 304 {
		if !m.emptyRepresentation {
			return representationUnavailable()
		}
		return d.CheckBody(nil)
	}
	if status == 206 && m.mediaType != "multipart/byteranges" {
		r := m.contentRange
		if r == nil || r.Unsatisfied || !r.CompleteKnown || r.First != 0 || r.Size != r.Complete {
			return representationUnavailable()
		}
	}
	return nil
}

// The complete-body backstop also covers trusted custom MCP transports.
// Multipart representation bytes are reconstructed only after proving bounded,
// continuous coverage and consistent overlaps in this one response.
func checkResponseRepresentationDigest(resp *http.Response, method string, body []byte) error {
	d, err := responseRepresentationDigests(resp.Header)
	if err != nil || !d.Present() {
		return err
	}
	m := responseMetadata{representationDigest: *d}
	for name, values := range resp.Header {
		switch strings.ToLower(name) {
		case "content-type", "content-range", "content-length":
			for _, value := range values {
				if err := m.add(name, strings.Trim(value, " ")); err != nil {
					return err
				}
			}
		}
	}
	if err := m.finishRepresentation(resp.StatusCode, method); err != nil {
		return err
	}
	requested, err := responseRanges(resp.Request)
	if err != nil {
		return err
	}
	partial, err := m.partial(resp.StatusCode, method, int64(len(body)), requested)
	if err != nil {
		return err
	}
	if partial != nil && partial.boundary != "" {
		return checkMultipartRangesForRequestAndDigest(body, partial.boundary, requested, d)
	}
	return d.CheckBody(body)
}
