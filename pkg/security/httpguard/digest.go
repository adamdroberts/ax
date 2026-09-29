package httpguard

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

const maxDigestMembers = 1024
const maxDigestParameters = 256 // Per member, as required by RFC 8941.

// RFC 9530 refers to RFC 8941: byte-sequence dictionary members with ordinary
// bare-item parameters. Date/display-string parameters belong to a later RFC.
// Unknown algorithms/parameters remain opaque. Local policy requires at least
// one supported strong algorithm and rejects duplicate algorithm keys instead
// of allowing Structured Fields' last-value-wins behavior. Digests authenticate
// neither their sender nor the meaning/safety of the content.
type ContentDigests struct {
	members      map[string][]byte
	fields, size int
}

func digestError() error { return fmt.Errorf("message violates the HTTP digest integrity policy") }

func (d *ContentDigests) Add(value string) error {
	d.fields++
	d.size += len(value)
	if d.fields > 128 || d.size > 64*1024 || len(value) > 8192 {
		return digestError()
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return digestError()
		}
	}
	p := digestParser{text: strings.Trim(value, " ")}
	if p.text == "" {
		return digestError()
	}
	if d.members == nil {
		d.members = map[string][]byte{}
	}
	for {
		key, ok := p.key()
		if !ok || !p.take('=') {
			return digestError()
		}
		if _, exists := d.members[key]; exists || len(d.members) >= maxDigestMembers {
			return digestError()
		}
		value, ok := p.binary()
		if !ok || key == "sha-256" && len(value) != sha256.Size || key == "sha-512" && len(value) != sha512.Size {
			return digestError()
		}
		d.members[key] = value
		if !p.parameters() {
			return digestError()
		}
		p.space()
		if p.position == len(p.text) {
			return nil
		}
		if !p.take(',') {
			return digestError()
		}
		p.space()
		if p.position == len(p.text) {
			return digestError()
		}
	}
}

func (d *ContentDigests) Ready() error {
	if d.fields > 0 && d.members["sha-256"] == nil && d.members["sha-512"] == nil {
		return digestError()
	}
	return nil
}

type digestParser struct {
	text     string
	position int
}

func (p *digestParser) parameters() bool {
	count := 0
	for p.take(';') {
		count++
		p.space()
		if _, ok := p.key(); !ok || count > maxDigestParameters {
			return false
		}
		if p.take('=') && !p.bare() {
			return false
		}
	}
	return true
}

func (p *digestParser) take(c byte) bool {
	if p.position == len(p.text) || p.text[p.position] != c {
		return false
	}
	p.position++
	return true
}
func (p *digestParser) space() {
	for p.position < len(p.text) && p.text[p.position] == ' ' {
		p.position++
	}
}
func (p *digestParser) key() (string, bool) {
	start := p.position
	if start == len(p.text) || !(p.text[start] >= 'a' && p.text[start] <= 'z' || p.text[start] == '*') {
		return "", false
	}
	for p.position < len(p.text) {
		c := p.text[p.position]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.*-", rune(c))) {
			break
		}
		p.position++
	}
	return p.text[start:p.position], true
}
func (p *digestParser) binary() ([]byte, bool) {
	if !p.take(':') {
		return nil, false
	}
	start := p.position
	for p.position < len(p.text) && p.text[p.position] != ':' {
		c := p.text[p.position]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, false
		}
		p.position++
	}
	end := p.position
	if !p.take(':') {
		return nil, false
	}
	encoded := p.text[start:end]
	unpadded := strings.TrimRight(encoded, "=")
	padding := (4 - len(unpadded)%4) % 4
	if len(unpadded)%4 == 1 || strings.Contains(unpadded, "=") || len(encoded)-len(unpadded) > padding {
		return nil, false
	}
	// RFC 8941 permits synthesizing missing padding and tolerates nonzero pad
	// bits. Alphabet, impossible lengths, embedded/excess padding stay invalid.
	decoded, err := base64.StdEncoding.DecodeString(unpadded + strings.Repeat("=", padding))
	return decoded, err == nil
}
func (p *digestParser) bare() bool {
	if p.position == len(p.text) {
		return false
	}
	c := p.text[p.position]
	if c == ':' {
		_, ok := p.binary()
		return ok
	}
	if c == '?' {
		p.position++
		return p.take('0') || p.take('1')
	}
	if c == '"' {
		p.position++
		for p.position < len(p.text) {
			c = p.text[p.position]
			p.position++
			if c == '"' {
				return true
			}
			if c == '\\' && !(p.take('\\') || p.take('"')) {
				return false
			}
		}
		return false
	}
	if c == '-' || c >= '0' && c <= '9' {
		p.take('-')
		start := p.position
		for p.position < len(p.text) && p.text[p.position] >= '0' && p.text[p.position] <= '9' {
			p.position++
		}
		digits := p.position - start
		if digits < 1 || digits > 15 {
			return false
		}
		if p.take('.') {
			start = p.position
			for p.position < len(p.text) && p.text[p.position] >= '0' && p.text[p.position] <= '9' {
				p.position++
			}
			return digits <= 12 && p.position-start >= 1 && p.position-start <= 3
		}
		return true
	}
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '*') {
		return false
	}
	for p.position < len(p.text) && (digestTokenByte(p.text[p.position]) || p.text[p.position] == ':' || p.text[p.position] == '/') {
		p.position++
	}
	return true
}

func ParseContentDigests(headers http.Header) (*ContentDigests, error) {
	return parseIntegrityDigests(headers, "Content-Digest")
}

func ParseRepresentationDigests(headers http.Header) (*ContentDigests, error) {
	return parseIntegrityDigests(headers, "Repr-Digest")
}

func parseIntegrityDigests(headers http.Header, field string) (*ContentDigests, error) {
	d := &ContentDigests{}
	seen := false
	for name, values := range headers {
		if !strings.EqualFold(name, field) {
			continue
		}
		if seen || len(values) == 0 {
			return nil, digestError()
		}
		seen = true
		for _, value := range values {
			if err := d.Add(value); err != nil {
				return nil, err
			}
		}
	}
	return d, d.Ready()
}

// Partial uploads cannot establish an entire representation digest unless
// Content-Range proves that this message carries every representation byte.
// Ordinary request content (including PATCH documents) is its representation.
func ParseRequestRepresentationDigests(headers http.Header) (*ContentDigests, error) {
	d, err := ParseRepresentationDigests(headers)
	if err != nil || !d.Present() {
		return d, err
	}
	seen := false
	for name, values := range headers {
		if !strings.EqualFold(name, "Content-Range") {
			continue
		}
		if seen || len(values) != 1 {
			return nil, digestError()
		}
		seen = true
		r, err := ParseContentRange(values[0])
		if err != nil || r.Unsatisfied || !r.CompleteKnown || r.First != 0 || r.Size != r.Complete {
			return nil, fmt.Errorf("representation digest requires complete representation data")
		}
	}
	return d, nil
}

func CheckRequestDigests(headers http.Header, body []byte) error {
	if err := CheckContentDigest(headers, body); err != nil {
		return err
	}
	d, err := ParseRequestRepresentationDigests(headers)
	if err != nil {
		return err
	}
	return d.CheckBody(body)
}

type digestHash struct {
	hash     hash.Hash
	expected []byte
}
type ContentDigestChecker []digestHash

func (d *ContentDigests) Checker() ContentDigestChecker {
	var result ContentDigestChecker
	if expected := d.members["sha-256"]; expected != nil {
		result = append(result, digestHash{sha256.New(), expected})
	}
	if expected := d.members["sha-512"]; expected != nil {
		result = append(result, digestHash{sha512.New(), expected})
	}
	return result
}
func (c ContentDigestChecker) Write(body []byte) {
	for _, entry := range c {
		entry.hash.Write(body)
	}
}
func (c ContentDigestChecker) Check() error {
	for _, entry := range c {
		if !bytes.Equal(entry.hash.Sum(nil), entry.expected) {
			return digestError()
		}
	}
	return nil
}
func (d *ContentDigests) CheckBody(body []byte) error {
	c := d.Checker()
	c.Write(body)
	return c.Check()
}

// Present reports whether at least one Content-Digest field was supplied.
func (d *ContentDigests) Present() bool { return d.fields != 0 }

// CheckContentDigest checks the exact message-content octets, without decoding
// media types, normalizing text, or interpreting representation digests.
func CheckContentDigest(headers http.Header, body []byte) error {
	d, err := ParseContentDigests(headers)
	if err != nil {
		return err
	}
	return d.CheckBody(body)
}

func digestTokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
