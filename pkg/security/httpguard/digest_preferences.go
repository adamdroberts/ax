package httpguard

import (
	"net/http"
	"strings"
)

// DigestPreferences validates RFC 9530 hints, not integrity evidence or policy
// overrides. Unknown algorithms and an empty dictionary are permitted. As with
// integrity fields, duplicate algorithm keys are denied by local policy.
type DigestPreferences struct {
	members      map[string]bool
	fields, size int
	empty        bool
}

func (d *DigestPreferences) Add(value string) error {
	d.fields++
	d.size += len(value)
	if d.fields > 128 || d.size > 64*1024 || len(value) > 8192 || d.empty {
		return digestError()
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return digestError()
		}
	}
	p := digestParser{text: strings.Trim(value, " ")}
	if p.text == "" {
		if d.fields != 1 {
			return digestError()
		}
		d.empty = true
		return nil
	}
	if d.members == nil {
		d.members = map[string]bool{}
	}
	for {
		key, ok := p.key()
		if !ok || !p.take('=') || d.members[key] || len(d.members) >= maxDigestMembers {
			return digestError()
		}
		if !p.preference() || !p.parameters() {
			return digestError()
		}
		d.members[key] = true
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

// RFC 8941 integers accept leading zeros and negative zero. Decimals and
// booleans remain different types even when their values resemble 0 or 1.
func (p *digestParser) preference() bool {
	negative := p.take('-')
	start, value := p.position, 0
	for p.position < len(p.text) && p.text[p.position] >= '0' && p.text[p.position] <= '9' {
		value = value*10 + int(p.text[p.position]-'0')
		p.position++
		if value > 10 || p.position-start > 15 {
			return false
		}
	}
	return p.position > start && (!negative || value == 0)
}

// ValidateDigestPreferences validates the two independent preference fields.
// It does not require a digest, select an algorithm, or waive digest checks.
func ValidateDigestPreferences(headers http.Header) error {
	fields := map[string]*DigestPreferences{}
	for name, values := range headers {
		name = strings.ToLower(name)
		if name != "want-content-digest" && name != "want-repr-digest" {
			continue
		}
		if fields[name] != nil || len(values) == 0 {
			return digestError()
		}
		d := &DigestPreferences{}
		fields[name] = d
		for _, value := range values {
			if err := d.Add(value); err != nil {
				return err
			}
		}
	}
	return nil
}
