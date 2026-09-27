package dnsproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A local fake resolver proves the bytes actually sent upstream and TCP fallback.
// Tests never query a public DNS service.
func upstreamServer(t *testing.T, truncate bool, mutate func(*dnsmessage.Message)) (string, func() []dnsmessage.Message) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []dnsmessage.Message
	var workers sync.WaitGroup
	reply := func(data []byte, tcp bool) []byte {
		var q dnsmessage.Message
		if err := q.Unpack(data); err != nil || len(q.Questions) != 1 {
			t.Error("bad upstream query", err)
			return nil
		}
		mu.Lock()
		requests = append(requests, q)
		mu.Unlock()
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RecursionDesired: true}, Questions: q.Questions}
		if truncate && !tcp {
			m.Truncated = true
		} else {
			alias, _ := dnsmessage.NewName("edge.example.test.")
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: 1, TTL: 40}, Body: &dnsmessage.CNAMEResource{CNAME: alias}})
			var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}
			if q.Questions[0].Type == dnsmessage.TypeAAAA {
				body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
			}
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Class: 1, TTL: 60}, Body: body})
			m.Additionals = append(m.Additionals, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Class: 1, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"OPAQUE_UPSTREAM_DATA"}}})
		}
		if mutate != nil {
			mutate(&m)
		}
		wire, err := m.Pack()
		if err != nil {
			t.Error(err)
		}
		return wire
	}
	workers.Go(func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = u.WriteTo(reply(buf[:n], false), addr)
		}
	})
	workers.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				var prefix [2]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					return
				}
				wire := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(c, wire); err != nil {
					return
				}
				out := reply(wire, true)
				binary.BigEndian.PutUint16(prefix[:], uint16(len(out)))
				buffers := net.Buffers{prefix[:], out}
				_, _ = buffers.WriteTo(c)
			})
		}
	})
	t.Cleanup(func() { u.Close(); l.Close(); workers.Wait() })
	return l.Addr().String(), func() []dnsmessage.Message {
		mu.Lock()
		defer mu.Unlock()
		return append([]dnsmessage.Message(nil), requests...)
	}
}

func TestPinnedUpstreamCanonicalQueriesAndTCFallback(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "UDP", true: "TCP-fallback"}[truncated], func(t *testing.T) {
			address, requests := upstreamServer(t, truncated, nil)
			r, err := PinnedResolver(address)
			if err != nil {
				t.Fatal(err)
			}
			p, err := New(Config{AllowedNames: []string{"API.EXAMPLE.TEST"}}, r)
			if err != nil {
				t.Fatal(err)
			}
			p.Refresh(context.Background())
			before := len(requests())
			want := 2
			if truncated {
				want = 4
			}
			if before != want {
				t.Fatal("unexpected upstream traffic", before)
			}
			for _, q := range requests() {
				if !q.RecursionDesired || q.CheckingDisabled || q.AuthenticData || q.Response || len(q.Questions) != 1 || q.Questions[0].Name.String() != "api.example.test." || len(q.Additionals) != 0 || len(q.Answers) != 0 {
					t.Fatal(q)
				}
			}
			wire := edns(query(t, "API.EXAMPLE.TEST.", 1), 0x8000, nil)
			binary.BigEndian.PutUint16(wire, 0xfeed)
			m := unpack(t, p.Answer(wire, false))
			if m.ID != 0xfeed || m.RCode != 0 || len(m.Answers) != 1 || m.Answers[0].Header.TTL > 40 || m.AuthenticData {
				t.Fatal(m)
			}
			for _, rr := range m.Answers {
				if _, ok := rr.Body.(*dnsmessage.AResource); !ok {
					t.Fatal("opaque upstream record leaked")
				}
			}
			for _, rr := range m.Additionals {
				if _, ok := rr.Body.(*dnsmessage.OPTResource); !ok {
					t.Fatal("upstream additional data leaked")
				}
			}
			for i := 0; i < 50; i++ {
				p.Answer(query(t, "ciphertext.api.example.test.", 16), false)
				p.Answer(wire, true)
			}
			if len(requests()) != before {
				t.Fatal("client packets scheduled upstream traffic")
			}
		})
	}
}

func TestUnmatchedUpstreamResponsesAreNotCached(t *testing.T) {
	cases := map[string]func(*dnsmessage.Message){
		"id":                func(m *dnsmessage.Message) { m.ID++ },
		"question":          func(m *dnsmessage.Message) { m.Questions[0].Name, _ = dnsmessage.NewName("unapproved.test.") },
		"type":              func(m *dnsmessage.Message) { m.Questions[0].Type = 16 },
		"class":             func(m *dnsmessage.Message) { m.Questions[0].Class = 3 },
		"response-bit":      func(m *dnsmessage.Message) { m.Response = false },
		"servfail":          func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure },
		"cname-cycle":       func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: m.Questions[0].Name} },
		"ttl-zero":          func(m *dnsmessage.Message) { m.Answers[0].Header.TTL = 0 },
		"ttl-high-bit":      func(m *dnsmessage.Message) { m.Answers[0].Header.TTL = 0x80000001 },
		"unrelated-address": func(m *dnsmessage.Message) { m.Answers[1].Header.Name, _ = dnsmessage.NewName("other.test.") },
		"mixed-private-address": func(m *dnsmessage.Message) {
			if m.Questions[0].Type == 1 {
				m.Answers[1].Body = &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			address, _ := upstreamServer(t, false, mutate)
			r, err := PinnedResolver(address)
			if err != nil {
				t.Fatal(err)
			}
			p, err := New(Config{AllowedNames: []string{"api.example.test"}}, r)
			if err != nil {
				t.Fatal(err)
			}
			p.Refresh(context.Background())
			if m := unpack(t, p.Answer(query(t, "api.example.test.", 1), false)); m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
				t.Fatal(m)
			}
		})
	}
}

func TestConcurrentRefreshAndClientQueries(t *testing.T) {
	p, _ := testProxy(t)
	wire := query(t, "api.example.test.", 1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 25; j++ {
				p.Answer(wire, false)
				_ = p.Stats()
			}
		})
	}
	wg.Go(func() {
		for j := 0; j < 10; j++ {
			p.Refresh(context.Background())
		}
	})
	wg.Wait()
}

func TestExactUpstreamEnvelope(t *testing.T) {
	wire := query(t, "api.example.test.", 1)
	if !exactEnvelope(wire) {
		t.Fatal("valid envelope rejected")
	}
	if exactEnvelope(append(append([]byte(nil), wire...), 1)) {
		t.Fatal("trailing bytes accepted")
	}
	for i := 0; i < len(wire); i++ {
		if exactEnvelope(wire[:i]) {
			t.Fatal("truncation accepted", i)
		}
	}
	wire[3] |= 0x40
	if exactEnvelope(wire) {
		t.Fatal("reserved header bit accepted")
	}
	wire[3] = 0
	wire[12] = 0xc0
	wire[13] = 12
	if exactEnvelope(wire) {
		t.Fatal("self pointer accepted")
	}
}

func FuzzUpstreamEnvelope(f *testing.F) {
	f.Add(query(f, "api.example.test.", 1))
	f.Fuzz(func(t *testing.T, data []byte) {
		if exactEnvelope(data) {
			var m dnsmessage.Message
			if m.Unpack(data) == nil {
				_, _, _ = extractAddresses(m, "api.example.test.", 1)
			}
		}
	})
}
