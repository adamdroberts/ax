package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func rawRecord(owner []byte, kind dnsmessage.Type, data []byte) []byte {
	rr := append([]byte(nil), owner...)
	rr = binary.BigEndian.AppendUint16(rr, uint16(kind))
	rr = binary.BigEndian.AppendUint16(rr, 1)
	rr = binary.BigEndian.AppendUint32(rr, 60)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(data)))
	return append(rr, data...)
}

func pointer(offset int) []byte {
	return []byte{0xc0 | byte(offset>>8), byte(offset)}
}

func TestUpstreamCompressionBoundaries(t *testing.T) {
	owner := pointer(12)
	questionEnd := len(query(t, "api.example.test.", 1))
	for _, tc := range []struct {
		name   string
		target int
		valid  bool
	}{
		{"question", 12, true}, {"suffix", 16, true}, {"root", 29, true},
		{"header", 4, false}, {"label-payload", 13, false},
		{"question-type", 30, false}, {"question-class", 32, false},
		{"owner-pointer", questionEnd, true}, {"rr-header", questionEnd + 2, false},
		{"self", questionEnd + 12, false}, {"future-record", questionEnd + 14, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := rawResponse(t, rawRecord(owner, dnsmessage.TypeCNAME, pointer(tc.target)), rawRecord(owner, dnsmessage.TypeA, []byte{8, 8, 8, 8}))
			if tc.name == "label-payload" {
				// A complete apparent name inside a literal label is not a
				// compression target, even if a permissive decoder accepts it.
				copy(wire[13:16], []byte{1, 'x', 0})
			}
			if exactEnvelope(wire) != tc.valid {
				t.Fatal("incorrect compression target acceptance")
			}
		})
	}
	for _, opaque := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior-rdata-opaque%t", opaque), func(t *testing.T) {
			kind := dnsmessage.TypeCNAME
			if opaque {
				kind = 65280
			}
			first := rawRecord(owner, kind, []byte{4, 'e', 'd', 'g', 'e', 0xc0, 16})
			wire := rawResponse(t, first, rawRecord(pointer(questionEnd+12), dnsmessage.TypeA, []byte{8, 8, 8, 8}))
			if exactEnvelope(wire) == opaque {
				t.Fatal("incorrect name provenance acceptance")
			}
		})
	}
	for _, data := range [][]byte{{0xc0}, {3, 'a', 'b'}, {0x40, 0}, {0x80, 0}, {0xc0, 0xff}} {
		wire := rawResponse(t, rawRecord(owner, dnsmessage.TypeCNAME, data), rawRecord(owner, dnsmessage.TypeA, []byte{8, 8, 8, 8}))
		if exactEnvelope(wire) {
			t.Fatalf("accepted truncated or invalid name %x", data)
		}
	}
}

func TestUpstreamExpandedNameLimits(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, size := range []int{255, 256} {
			t.Run(fmt.Sprintf("compressed%t-size%d", compressed, size), func(t *testing.T) {
				var name []byte
				for i := 0; i < 3; i++ {
					name = append(name, 63)
					name = append(name, bytes.Repeat([]byte{'a'}, 63)...)
				}
				last := size - len(name) - 2
				if compressed {
					last -= 17 // question suffix expands to 18 octets instead of a root
				}
				name = append(name, byte(last))
				name = append(name, bytes.Repeat([]byte{'b'}, last)...)
				if compressed {
					name = append(name, pointer(12)...)
				} else {
					name = append(name, 0)
				}
				if exactEnvelope(rawResponse(t, rawRecord(pointer(12), dnsmessage.TypeCNAME, name))) != (size == 255) {
					t.Fatal("incorrect expanded name length acceptance")
				}
			})
		}
	}
	for _, labels := range []int{127, 128} {
		name := append(bytes.Repeat([]byte{1, 'a'}, labels), 0)
		if exactEnvelope(rawResponse(t, rawRecord(pointer(12), dnsmessage.TypeCNAME, name))) != (labels == 127) {
			t.Fatal("incorrect label count acceptance", labels)
		}
	}
}

func TestUpstreamStructuredRData(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  dnsmessage.Type
		data  []byte
		valid bool
	}{
		{"txt-empty-string", 16, []byte{0}, true},
		{"txt-multiple", 16, []byte{1, 'x', 1, 'y'}, true},
		{"txt-no-strings", 16, nil, false},
		{"txt-short", 16, []byte{3, 'x'}, false},
		{"hinfo", 13, []byte{0, 0}, true},
		{"hinfo-missing-os", 13, []byte{0}, false},
		{"hinfo-extra", 13, []byte{0, 0, 0}, false},
		{"minfo", 14, []byte{0xc0, 12, 0xc0, 12}, true},
		{"minfo-short", 14, []byte{0xc0, 12}, false},
		{"legacy-md", 3, []byte{0xc0, 12}, true},
		{"legacy-srv-compression", 33, []byte{0, 0, 0, 0, 0, 53, 0xc0, 12}, true},
		{"srv-short", 33, []byte{0, 0, 0, 0, 0, 53}, false},
		{"opt-empty", 41, nil, true},
		{"opt-option", 41, []byte{0, 12, 0, 1, 0}, true},
		{"opt-short-header", 41, []byte{0, 12, 0}, false},
		{"opt-short-value", 41, []byte{0, 12, 0, 1}, false},
		{"svcb", 64, []byte{0, 1, 0}, true},
		{"https-params", 65, []byte{0, 1, 0, 0, 2, 0, 0, 0, 3, 0, 2, 1, 187}, true},
		{"https-compressed-target", 65, []byte{0, 1, 0xc0, 12}, false},
		{"https-no-target", 65, []byte{0, 1}, false},
		{"https-short-priority", 65, []byte{0}, false},
		{"https-short-param-header", 65, []byte{0, 1, 0, 0, 3, 0}, false},
		{"https-short-param-value", 65, []byte{0, 1, 0, 0, 3, 0, 2, 1}, false},
		{"https-repeated-key", 65, []byte{0, 1, 0, 0, 2, 0, 0, 0, 2, 0, 0}, false},
		{"https-unordered-key", 65, []byte{0, 1, 0, 0, 3, 0, 0, 0, 2, 0, 0}, false},
		{"unknown-opaque", 65280, []byte{0xc0, 0xff, 0x80, 0xff}, true},
		{"unknown-empty", 65280, nil, true},
	} {
		for _, section := range []int{6, 8, 10} {
			t.Run(fmt.Sprintf("%s-section%d", tc.name, section), func(t *testing.T) {
				owner := pointer(12)
				if tc.kind == dnsmessage.TypeOPT {
					owner = []byte{0}
				}
				wire := rawResponse(t, rawRecord(owner, tc.kind, tc.data))
				wire[7] = 0
				wire[section+1] = 1
				if exactEnvelope(wire) != tc.valid {
					t.Fatal("incorrect RDATA framing acceptance")
				}
			})
		}
	}
}

func TestMalformedUpstreamRefreshRemovesCachedAddresses(t *testing.T) {
	for _, mode := range []string{"short-A", "padded-A", "short-AAAA", "padded-AAAA", "forward-CNAME", "alias-opposite-family"} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-tcp%t", mode, tcp), func(t *testing.T) {
				var corrupt atomic.Bool
				questionEnd := len(query(t, "api.example.test.", 1))
				address, requests := upstreamWireServer(t, tcp, nil, func(wire []byte) []byte {
					if !corrupt.Load() || wire[2]&2 != 0 {
						return wire
					}
					kind := dnsmessage.Type(binary.BigEndian.Uint16(wire[questionEnd-4:]))
					var records [][]byte
					data := []byte{8, 8, 8, 8}
					if kind == dnsmessage.TypeAAAA {
						data = netip.MustParseAddr("2606:4700:4700::1111").AsSlice()
					}
					switch mode {
					case "short-A", "padded-A", "short-AAAA", "padded-AAAA":
						if (mode == "short-A" || mode == "padded-A") != (kind == dnsmessage.TypeA) {
							return wire
						}
						if mode == "short-A" || mode == "short-AAAA" {
							data = data[:len(data)-1]
						} else {
							data = append(data, 0x41)
						}
						records = [][]byte{rawRecord(pointer(12), kind, data), rawRecord(pointer(12), 65280, nil)}
					case "forward-CNAME":
						target := []byte{4, 'e', 'd', 'g', 'e', 0xc0, 16}
						records = [][]byte{rawRecord(pointer(12), dnsmessage.TypeCNAME, pointer(questionEnd+14)), rawRecord(target, kind, data)}
					case "alias-opposite-family":
						var m dnsmessage.Message
						if err := m.Unpack(wire); err != nil {
							t.Error(err)
							return nil
						}
						body := dnsmessage.ResourceBody(&dnsmessage.AResource{A: [4]byte{8, 8, 4, 4}})
						if kind == dnsmessage.TypeA {
							body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1001").As16()}
						}
						m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: 1, TTL: 60}, Body: body})
						out, err := m.Pack()
						if err != nil {
							t.Error(err)
						}
						return out
					}
					out := bytes.Clone(wire[:questionEnd])
					clear(out[6:12])
					binary.BigEndian.PutUint16(out[6:], uint16(len(records)))
					for _, rr := range records {
						out = append(out, rr...)
					}
					return out
				})
				r, err := PinnedResolver(address)
				if err != nil {
					t.Fatal(err)
				}
				p, err := New(Config{AllowedNames: []string{"api.example.test"}}, r)
				if err != nil {
					t.Fatal(err)
				}
				for _, bad := range []bool{false, true, false} {
					corrupt.Store(bad)
					p.Refresh(context.Background())
					before := len(requests())
					for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
						m := unpack(t, p.Answer(query(t, "api.example.test.", kind), false))
						if bad && (m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0) {
							t.Fatal("bad refresh exposed partial or stale answers", m)
						}
						if !bad && (m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1) {
							t.Fatal("valid refresh failed to recover", m)
						}
					}
					if len(requests()) != before {
						t.Fatal("client caused upstream traffic")
					}
				}
			})
		}
	}
}

func rawResponse(t testing.TB, records ...[]byte) []byte {
	t.Helper()
	wire := query(t, "api.example.test.", 1)
	wire[2], wire[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(wire[6:8], uint16(len(records)))
	for _, rr := range records {
		wire = append(wire, rr...)
	}
	return wire
}

func TestUpstreamAddressRecordLengths(t *testing.T) {
	owner := []byte{0xc0, 12}
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		size := 4
		if kind == dnsmessage.TypeAAAA {
			size = 16
		}
		for _, length := range []int{0, size - 1, size, size + 1, size + 4} {
			t.Run(fmt.Sprintf("type%d-length%d", kind, length), func(t *testing.T) {
				data := make([]byte, length)
				for i := range data {
					data[i] = 8
				}
				// A following complete RR makes short RDATA reads possible in
				// the generic decoder; exact RR boundaries must reject them.
				wire := rawResponse(t, rawRecord(owner, kind, data), rawRecord(owner, dnsmessage.TypeA, []byte{8, 8, 4, 4}))
				var parsed dnsmessage.Message
				if err := parsed.Unpack(wire); err != nil && length >= size-1 {
					t.Fatal("fixture no longer exercises generic decoder acceptance", err)
				}
				if exactEnvelope(wire) != (length == size) {
					t.Fatal("incorrect RDATA length acceptance", kind, length)
				}
			})
		}
	}
}

func TestUpstreamNameRecordBoundaries(t *testing.T) {
	owner := []byte{0xc0, 12}
	alias := []byte{4, 'e', 'd', 'g', 'e', 0xc0, 16}
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypePTR, dnsmessage.TypeMX, dnsmessage.TypeSOA, dnsmessage.TypeSRV} {
		for _, padded := range []bool{false, true} {
			t.Run(fmt.Sprintf("type%d-padded%t", kind, padded), func(t *testing.T) {
				data := append([]byte(nil), alias...)
				switch kind {
				case dnsmessage.TypeMX:
					data = append([]byte{0, 10}, data...)
				case dnsmessage.TypeSOA:
					data = append(data, alias...)
					data = append(data, make([]byte, 20)...)
				case dnsmessage.TypeSRV:
					data = append([]byte{0, 0, 0, 0, 0, 53}, []byte{4, 'e', 'd', 'g', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}...)
				}
				if padded {
					data = append(data, 0x41)
				}
				wire := rawResponse(t, rawRecord(owner, kind, data))
				var parsed dnsmessage.Message
				if err := parsed.Unpack(wire); err != nil {
					t.Fatal("fixture did not parse", err)
				}
				if exactEnvelope(wire) == padded {
					t.Fatal("incorrect name RDATA boundary acceptance")
				}
			})
		}
	}
}

func TestUpstreamCNAMECoexistence(t *testing.T) {
	name, target := dnsmessage.MustNewName("api.example.test."), dnsmessage.MustNewName("edge.example.test.")
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		for _, conflict := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.Type(65280)} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("query%d-conflict%d-reverse%t", kind, conflict, reverse), func(t *testing.T) {
					header := dnsmessage.ResourceHeader{Name: name, Class: 1, TTL: 60}
					alias := dnsmessage.Resource{Header: header, Body: &dnsmessage.CNAMEResource{CNAME: target}}
					other := dnsmessage.Resource{Header: header}
					switch conflict {
					case dnsmessage.TypeA:
						other.Body = &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}
					case dnsmessage.TypeAAAA:
						other.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
					case dnsmessage.TypeTXT:
						other.Body = &dnsmessage.TXTResource{TXT: []string{"ignored"}}
					case dnsmessage.TypeMX:
						other.Body = &dnsmessage.MXResource{MX: target}
					default:
						other.Body = &dnsmessage.UnknownResource{Type: conflict, Data: []byte{1}}
					}
					answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: target, Class: 1, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 4, 4}}}
					if kind == dnsmessage.TypeAAAA {
						answer.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1001").As16()}
					}
					records := []dnsmessage.Resource{alias, other, answer}
					if reverse {
						records = []dnsmessage.Resource{answer, other, alias}
					}
					wire, err := (&dnsmessage.Message{Answers: records}).Pack()
					if err != nil {
						t.Fatal(err)
					}
					var parsed dnsmessage.Message
					if err := parsed.Unpack(wire); err != nil {
						t.Fatal(err)
					}
					if _, _, err := extractAddresses(parsed, name.String(), kind); err == nil {
						t.Fatal("conflicting alias RRset accepted")
					}
				})
			}
		}
	}
}

func TestUpstreamCNAMEValidDNSSECCompanions(t *testing.T) {
	name, target := dnsmessage.MustNewName("api.example.test."), dnsmessage.MustNewName("edge.example.test.")
	m := dnsmessage.Message{Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name, Class: 1, TTL: 40}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
		{Header: dnsmessage.ResourceHeader{Name: target, Class: 1, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}},
	}}
	// These companion types are permitted at a CNAME owner by RFC 4035 2.5.
	// Their opaque data is not authenticated or exposed by the address broker.
	for _, kind := range []dnsmessage.Type{25, 46, 47} {
		m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: kind, Class: 1, TTL: 20},
			Body: &dnsmessage.UnknownResource{Type: kind, Data: []byte{1}}})
	}
	ips, ttl, err := extractAddresses(m, name.String(), dnsmessage.TypeA)
	if err != nil || len(ips) != 1 || ips[0].String() != "8.8.8.8" || ttl != 40*time.Second {
		t.Fatal(ips, ttl, err)
	}
}
