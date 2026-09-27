// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package dnsproxy

import (
	"encoding/binary"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type question struct {
	id      uint16
	rd      bool
	name    string
	wire    dnsmessage.Question
	edns    bool
	udpSize int
}

// This is a deliberately restricted stub contract, not a recursive DNS parser.
// One uncompressed IN A/AAAA question and optionally an empty EDNS(0) OPT are
// admitted. Compression, extra records/options, non-host labels, CD, updates,
// transfers and opaque trailing bytes are refused before cache access.
func parseQuery(data []byte) (question, dnsmessage.RCode) {
	var q question
	if len(data) < 12 || len(data) > MaxQueryBytes {
		return q, dnsmessage.RCodeFormatError
	}
	q.id = binary.BigEndian.Uint16(data)
	flags := binary.BigEndian.Uint16(data[2:])
	q.rd = flags&0x100 != 0
	if flags & ^uint16(0x120) != 0 {
		return q, dnsmessage.RCodeRefused
	}
	if binary.BigEndian.Uint16(data[4:]) != 1 || binary.BigEndian.Uint16(data[6:]) != 0 || binary.BigEndian.Uint16(data[8:]) != 0 {
		return q, dnsmessage.RCodeFormatError
	}
	additional := binary.BigEndian.Uint16(data[10:])
	if additional > 1 {
		return q, dnsmessage.RCodeRefused
	}
	pos := 12
	var name []byte
	for {
		if pos >= len(data) {
			return q, dnsmessage.RCodeFormatError
		}
		n := int(data[pos])
		pos++
		if n == 0 {
			break
		}
		if n > 63 || pos+n > len(data) {
			return q, dnsmessage.RCodeFormatError
		}
		// Reject separators embedded in a label rather than reparsing them as
		// multiple labels with a different meaning.
		for _, c := range data[pos : pos+n] {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return q, dnsmessage.RCodeRefused
			}
		}
		name = append(name, data[pos:pos+n]...)
		name = append(name, '.')
		pos += n
		if len(name) > 254 {
			return q, dnsmessage.RCodeFormatError
		}
	}
	if pos+4 > len(data) {
		return q, dnsmessage.RCodeFormatError
	}
	canonical, err := canonicalName(string(name))
	if err != nil {
		return q, dnsmessage.RCodeRefused
	}
	q.name = canonical
	q.wire.Name, err = dnsmessage.NewName(string(name))
	if err != nil {
		return q, dnsmessage.RCodeFormatError
	}
	q.wire.Type = dnsmessage.Type(binary.BigEndian.Uint16(data[pos:]))
	q.wire.Class = dnsmessage.Class(binary.BigEndian.Uint16(data[pos+2:]))
	pos += 4
	if q.wire.Class != dnsmessage.ClassINET || (q.wire.Type != dnsmessage.TypeA && q.wire.Type != dnsmessage.TypeAAAA) {
		return q, dnsmessage.RCodeRefused
	}
	q.udpSize = 512
	if additional == 1 {
		// OPT: root owner, type 41, payload size, ext-rcode/version/flags,
		// RDLEN=0. DO is accepted locally but never forwarded or asserted.
		if pos+11 != len(data) || data[pos] != 0 || binary.BigEndian.Uint16(data[pos+1:]) != 41 {
			return q, dnsmessage.RCodeFormatError
		}
		if binary.BigEndian.Uint32(data[pos+5:]) & ^uint32(0x8000) != 0 || binary.BigEndian.Uint16(data[pos+9:]) != 0 {
			return q, dnsmessage.RCodeRefused
		}
		q.edns = true
		q.udpSize = max(512, min(1232, int(binary.BigEndian.Uint16(data[pos+3:]))))
		pos += 11
	}
	if pos != len(data) {
		return q, dnsmessage.RCodeFormatError
	}
	return q, dnsmessage.RCodeSuccess
}

// Answer returns only locally reconstructed address records. It performs no
// network I/O, even on a miss, expiration, denial, malformed or encrypted input.
// An incoming response or undersized packet is silently discarded.
func (p *Proxy) Answer(data []byte, tcp bool) []byte {
	p.queries.Add(1)
	if len(data) < 12 || data[2]&0x80 != 0 {
		p.denied.Add(1)
		return nil
	}
	q, code := parseQuery(data)
	if code != dnsmessage.RCodeSuccess {
		p.denied.Add(1)
		// No attacker-selected question bytes are echoed in error responses.
		out := make([]byte, 12)
		copy(out[:2], data[:2])
		binary.BigEndian.PutUint16(out[2:], 0x8080|uint16(code)|(binary.BigEndian.Uint16(data[2:])&0x100))
		return out
	}
	if _, ok := p.allowed[q.name]; !ok {
		p.denied.Add(1)
		return encodeReply(q, entry{code: dnsmessage.RCodeRefused}, false)
	}
	p.mu.RLock()
	e, exists := p.cache[q.name]
	p.mu.RUnlock()
	if !exists || !time.Now().Before(e.expires) {
		e = entry{code: dnsmessage.RCodeServerFailure}
	}
	if e.code != dnsmessage.RCodeSuccess {
		p.denied.Add(1)
	}
	reply := encodeReply(q, e, false)
	if !tcp && len(reply) > q.udpSize {
		return encodeReply(q, e, true)
	}
	return reply
}

func encodeReply(q question, e entry, truncated bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.id, Response: true,
		RecursionDesired: q.rd, RecursionAvailable: true, RCode: e.code, Truncated: truncated})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q.wire) != nil || b.StartAnswers() != nil {
		return nil
	}
	ttl := uint32(max(0, time.Until(e.expires).Seconds()))
	if e.code == dnsmessage.RCodeSuccess && !truncated {
		for _, ip := range e.addresses {
			h := dnsmessage.ResourceHeader{Name: q.wire.Name, Class: dnsmessage.ClassINET, TTL: ttl}
			if q.wire.Type == dnsmessage.TypeA && ip.Is4() {
				if b.AResource(h, dnsmessage.AResource{A: ip.As4()}) != nil {
					return nil
				}
			} else if q.wire.Type == dnsmessage.TypeAAAA && ip.Is6() {
				if b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: ip.As16()}) != nil {
					return nil
				}
			}
		}
	}
	if q.edns {
		root, _ := dnsmessage.NewName(".")
		if b.StartAdditionals() != nil || b.OPTResource(dnsmessage.ResourceHeader{Name: root, Class: 1232}, dnsmessage.OPTResource{}) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
