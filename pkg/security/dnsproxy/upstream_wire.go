// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package dnsproxy

import (
	"encoding/binary"

	"golang.org/x/net/dns/dnsmessage"
)

// upstreamWire checks field boundaries before dnsmessage decodes the packet.
// Some of its typed decoders read beyond RDLENGTH or ignore padding. Suffixes
// contain expanded wire lengths only at previously validated name boundaries;
// pointers cannot reinterpret headers, label payloads or opaque RDATA as names.
// This broker deliberately rejects references into unrecognized RR formats.
type upstreamWire struct {
	data     []byte
	suffixes [4096]uint16
}

// name returns the end of the encoded name, bounded by its enclosing field.
// Previously checked suffix lengths avoid recursively following pointer chains.
func (w *upstreamWire) name(pos, end int, compression bool) (int, bool) {
	if pos < 12 || end > len(w.data) || pos >= end {
		return 0, false
	}
	var labels [127]int // at most 127 one-octet labels in a 255-octet name
	count := 0
	for pos < end {
		start := pos
		n := int(w.data[pos])
		pos++
		length := 0
		switch {
		case n == 0:
			length = 1
		case n&0xc0 == 0xc0:
			if !compression || pos >= end {
				return 0, false
			}
			target := (n&0x3f)<<8 | int(w.data[pos])
			pos++
			if target < 12 || target >= start || w.suffixes[target] == 0 {
				return 0, false
			}
			length = int(w.suffixes[target])
		default:
			if n > 63 || pos+n > end || count == len(labels) {
				return 0, false
			}
			labels[count] = start
			count++
			pos += n
			continue
		}
		w.suffixes[start] = uint16(length)
		for i := count - 1; i >= 0; i-- {
			length += 1 + int(w.data[labels[i]])
			if length > 255 {
				return 0, false
			}
			w.suffixes[labels[i]] = uint16(length)
		}
		return pos, true
	}
	return 0, false
}

func (w *upstreamWire) names(pos, end, count, tail int, compression bool) bool {
	for i := 0; i < count; i++ {
		var ok bool
		pos, ok = w.name(pos, end, compression)
		if !ok {
			return false
		}
	}
	return pos+tail == end
}

func (w *upstreamWire) text(pos, end, count int) bool {
	strings := 0
	for pos < end {
		pos += 1 + int(w.data[pos])
		if pos > end {
			return false
		}
		strings++
	}
	return strings > 0 && (count == 0 || strings == count)
}

func (w *upstreamWire) options(pos, end int, ordered bool) bool {
	previous := -1
	for pos < end {
		if pos+4 > end {
			return false
		}
		key := int(binary.BigEndian.Uint16(w.data[pos:]))
		if ordered && key <= previous {
			return false
		}
		previous = key
		pos += 4 + int(binary.BigEndian.Uint16(w.data[pos+2:]))
		if pos > end {
			return false
		}
	}
	return true
}

func (w *upstreamWire) rdata(kind dnsmessage.Type, pos, end int) bool {
	switch kind {
	case dnsmessage.TypeA:
		return end-pos == 4
	case dnsmessage.TypeAAAA:
		return end-pos == 16
	case dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypePTR, 3, 4, 7, 8, 9:
		// Includes RFC 1035's obsolete MD, MF, MB, MG and MR formats.
		return w.names(pos, end, 1, 0, true)
	case dnsmessage.TypeSOA:
		return w.names(pos, end, 2, 20, true)
	case 14: // MINFO
		return w.names(pos, end, 2, 0, true)
	case dnsmessage.TypeMX:
		return w.names(pos+2, end, 1, 0, true)
	case 13: // HINFO: CPU and OS character strings
		return w.text(pos, end, 2)
	case dnsmessage.TypeTXT:
		return w.text(pos, end, 0)
	case dnsmessage.TypeSRV:
		// RFC 3597 section 4 recommends receiving legacy compressed SRV
		// targets even though RFC 2782 prohibits senders compressing them.
		return w.names(pos+6, end, 1, 0, true)
	case dnsmessage.TypeOPT:
		return w.options(pos, end, false)
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		// RFC 9460: priority, uncompressed TargetName, ordered unique TLVs.
		// Values are discarded; this does not validate every SvcParam's meaning.
		pos, ok := w.name(pos+2, end, false)
		return ok && w.options(pos, end, true)
	default:
		// RFC 3597: unknown RDATA stays opaque, including apparent pointers.
		return true
	}
}

func exactEnvelope(data []byte) bool {
	if len(data) < 12 || len(data) > 4096 || data[3]&0x40 != 0 {
		return false
	}
	w := upstreamWire{data: data}
	pos := 12
	for section := 0; section < 4; section++ {
		count := int(binary.BigEndian.Uint16(data[4+2*section:]))
		for i := 0; i < count; i++ {
			var ok bool
			pos, ok = w.name(pos, len(data), true)
			if !ok {
				return false
			}
			if section == 0 {
				pos += 4
				if pos > len(data) {
					return false
				}
				continue
			}
			if pos+10 > len(data) {
				return false
			}
			kind := dnsmessage.Type(binary.BigEndian.Uint16(data[pos:]))
			end := pos + 10 + int(binary.BigEndian.Uint16(data[pos+8:]))
			if end > len(data) || !w.rdata(kind, pos+10, end) {
				return false
			}
			pos = end
		}
	}
	return pos == len(data)
}
