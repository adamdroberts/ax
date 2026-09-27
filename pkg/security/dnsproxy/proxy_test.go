package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeResolver struct {
	mu     sync.Mutex
	names  []string
	result Resolution
	err    error
}

func (f *fakeResolver) Resolve(_ context.Context, name string) (Resolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names = append(f.names, name)
	return f.result, f.err
}
func (f *fakeResolver) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.names) }
func fakePublic() *fakeResolver {
	return &fakeResolver{result: Resolution{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")}, TTL: time.Minute}}
}
func testProxy(t *testing.T) (*Proxy, *fakeResolver) {
	t.Helper()
	r := fakePublic()
	p, err := New(Config{AllowedNames: []string{"api.example.test"}, ClientNets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Refresh(context.Background())
	return p, r
}
func query(t testing.TB, name string, kind dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: kind, Class: dnsmessage.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func unpack(t testing.TB, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("invalid response: %v (%x)", err, b)
	}
	return m
}
func edns(b []byte, flags uint32, extra []byte) []byte {
	b = append([]byte(nil), b...)
	binary.BigEndian.PutUint16(b[10:], 1)
	opt := make([]byte, 11)
	binary.BigEndian.PutUint16(opt[1:], 41)
	binary.BigEndian.PutUint16(opt[3:], 1232)
	binary.BigEndian.PutUint32(opt[5:], flags)
	binary.BigEndian.PutUint16(opt[9:], uint16(len(extra)))
	return append(append(b, opt...), extra...)
}

func TestExactNamesAndNoClientTriggeredResolution(t *testing.T) {
	p, r := testProxy(t)
	for _, name := range []string{"api.example.test.", "API.EXAMPLE.TEST."} {
		for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			response := unpack(t, p.Answer(query(t, name, kind), false))
			if response.RCode != 0 || len(response.Answers) != 1 || response.ID != 0x1234 || response.AuthenticData || response.Authoritative || response.Questions[0].Name.String() != name {
				t.Fatal(response)
			}
			if response.Answers[0].Header.TTL > 60 {
				t.Fatal("TTL exceeds upstream")
			}
		}
	}
	for _, name := range []string{"encoded.api.example.test.", "api.example.test.evil.test.", "elsewhere.test.", "0123456789abcdef0123456789abcdef.api.example.test."} {
		for i := 0; i < 20; i++ {
			response := unpack(t, p.Answer(query(t, name, dnsmessage.TypeA), true))
			if response.RCode != dnsmessage.RCodeRefused || len(response.Answers) != 0 {
				t.Fatal(response)
			}
		}
	}
	if r.count() != 1 || len(p.cache) != 1 {
		t.Fatal("client requests caused upstream I/O or cache growth", r.count(), len(p.cache))
	}
	if r.names[0] != "api.example.test." {
		t.Fatal(r.names)
	}
}

func TestStrictQueryContractAndEncryptedInputs(t *testing.T) {
	p, r := testProxy(t)
	base := query(t, "api.example.test.", dnsmessage.TypeA)
	cases := map[string][]byte{}
	for _, kind := range []dnsmessage.Type{2, 5, 10, 15, 16, 41, 65, 251, 252, 255, 65280} {
		cases[fmt.Sprintf("type-%d", kind)] = query(t, "api.example.test.", kind)
	}
	for _, flags := range []uint16{0x10, 0x40, 0x80, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 1} {
		b := bytes.Clone(base)
		binary.BigEndian.PutUint16(b[2:], flags|0x100)
		cases[fmt.Sprintf("flags-%x", flags)] = b
	}
	for _, offset := range []int{4, 6, 8, 10} {
		b := bytes.Clone(base)
		binary.BigEndian.PutUint16(b[offset:], 2)
		cases[fmt.Sprintf("count-%d", offset)] = b
	}
	b := bytes.Clone(base)
	b[len(b)-1] = 3
	cases["non-IN"] = b
	b = bytes.Clone(base)
	b[12] = 64
	cases["long-label"] = b
	b = bytes.Clone(base)
	b[12] = 0xc0
	b[13] = 12
	cases["compression-loop"] = b
	b = bytes.Clone(base)
	b[13] = '.'
	cases["dot-inside-label"] = b
	b = bytes.Clone(base)
	b[13] = 0xff
	cases["binary-label"] = b
	cases["trailing-data"] = append(bytes.Clone(base), []byte("encrypted payload")...)
	cases["oversized"] = append(bytes.Clone(base), make([]byte, 600)...)
	cases["root"] = query(t, ".", dnsmessage.TypeA)
	cases["EDNS-cookie"] = edns(base, 0, []byte{0, 10, 0, 4, 1, 2, 3, 4})
	cases["EDNS-subnet"] = edns(base, 0, []byte{0, 8, 0, 4, 1, 2, 3, 4})
	cases["EDNS-padding"] = edns(base, 0, []byte{0, 12, 0, 4, 1, 2, 3, 4})
	cases["EDNS-unknown"] = edns(base, 0, []byte{255, 255, 0, 4, 1, 2, 3, 4})
	cases["EDNS-version"] = edns(base, 0x10000, nil)
	cases["EDNS-reserved"] = edns(base, 1, nil)
	cases["DoT-TLS"] = append([]byte{0x16, 3, 3, 0, 64}, make([]byte, 64)...)
	cases["DoQ-QUIC"] = append([]byte{0xc0, 0, 0, 0, 1, 0, 0}, make([]byte, 50)...)
	cases["DoH-HTTP"] = []byte("GET /dns-query?dns=ciphertext HTTP/1.1\r\nHost: example.test\r\n\r\n")
	cases["DNSCrypt"] = append([]byte("DNSCrypt"), make([]byte, 64)...)
	for i := 0; i < len(base); i++ {
		cases[fmt.Sprintf("truncation-%d", i)] = base[:i]
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			for _, tcp := range []bool{false, true} {
				out := p.Answer(request, tcp)
				if out != nil {
					m := unpack(t, out)
					if m.RCode == 0 || len(m.Answers) != 0 {
						t.Fatal("invalid query admitted", m)
					}
				}
			}
		})
	}
	for _, request := range [][]byte{base, edns(base, 0, nil), edns(base, 0x8000, nil)} {
		response := unpack(t, p.Answer(request, false))
		if response.RCode != 0 || len(response.Answers) != 1 || response.AuthenticData {
			t.Fatal(response)
		}
	}
	if r.count() != 1 {
		t.Fatal("malformed/opaque requests reached upstream")
	}
}

func TestCacheExpirationRefreshFailureAndAddressSets(t *testing.T) {
	for _, ips := range [][]string{{"8.8.8.8", "10.0.0.1"}, {"::ffff:8.8.8.8"}, {"2001:db8::1"}, {"127.0.0.1"}, {"169.254.169.254"}, {"224.0.0.1"}, {}} {
		t.Run(strings.Join(ips, ","), func(t *testing.T) {
			p, r := testProxy(t)
			r.result.Addresses = nil
			for _, ip := range ips {
				r.result.Addresses = append(r.result.Addresses, netip.MustParseAddr(ip))
			}
			p.Refresh(context.Background())
			if m := unpack(t, p.Answer(query(t, "api.example.test.", 1), false)); m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
				t.Fatal(m)
			}
		})
	}
	p, r := testProxy(t)
	e := p.cache["api.example.test."]
	e.expires = time.Now().Add(-time.Second)
	p.cache["api.example.test."] = e
	if unpack(t, p.Answer(query(t, "api.example.test.", 1), false)).RCode != dnsmessage.RCodeServerFailure || r.count() != 1 {
		t.Fatal("expired cache triggered refresh or returned stale data")
	}
	r.err = fmt.Errorf("upstream unavailable")
	p.Refresh(context.Background())
	if unpack(t, p.Answer(query(t, "api.example.test.", 1), false)).RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("failed refresh retained old answer")
	}
	r.err = nil
	r.result.TTL = 0
	p.Refresh(context.Background())
	if unpack(t, p.Answer(query(t, "api.example.test.", 1), false)).RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("zero TTL was cached")
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	for _, name := range []string{"*.example.test", "example.test..", "single", "api._srv.test", "a..test", "-a.test", "a-.test", "api.example.test\x00", "1.2.3.4", strings.Repeat("a", 64) + ".test"} {
		if _, err := New(Config{AllowedNames: []string{name}}, fakePublic()); err == nil {
			t.Error("accepted", name)
		}
	}
	for _, cfg := range []Config{{AllowedNames: []string{"api.test", "API.TEST."}}, {AllowedNames: make([]string, MaxNames+1)}, {RefreshInterval: time.Second}, {LookupTimeout: time.Hour}, {ClientNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}}} {
		if _, err := New(cfg, fakePublic()); err == nil {
			t.Error("accepted invalid configuration")
		}
	}
	if _, err := New(Config{AllowedNames: []string{"api.test"}}, nil); err == nil {
		t.Fatal("missing upstream accepted")
	}
	p, err := New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.clientAllowed(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}) {
		t.Fatal("empty clients allowed source")
	}
	if unpack(t, p.Answer(query(t, "api.test.", 1), false)).RCode != dnsmessage.RCodeRefused {
		t.Fatal("empty names allowed query")
	}
	for _, addr := range []string{"resolver.example:53", "8.8.8.8", "0.0.0.0:53", "[::]:53", "224.0.0.1:53", "8.8.8.8:0", "[::ffff:8.8.8.8]:53", "[fe80::1%en0]:53"} {
		if _, err := PinnedResolver(addr); err == nil {
			t.Error("accepted invalid upstream", addr)
		}
	}
}

func TestExplicitAnswerNetworksAndTruncation(t *testing.T) {
	r := fakePublic()
	r.result.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.2")}
	p, err := New(Config{AllowedNames: []string{"broker.example.test"}, AnswerNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Refresh(context.Background())
	if unpack(t, p.Answer(query(t, "broker.example.test.", 1), false)).RCode != 0 {
		t.Fatal("explicit private answer not admitted")
	}
	r.result.Addresses = append(r.result.Addresses, netip.MustParseAddr("8.8.8.8"))
	p.Refresh(context.Background())
	if unpack(t, p.Answer(query(t, "broker.example.test.", 1), false)).RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("answer escaped configured range")
	}
	p, r = testProxy(t)
	r.result.Addresses = nil
	for i := 1; i <= MaxAnswers; i++ {
		r.result.Addresses = append(r.result.Addresses, netip.MustParseAddr(fmt.Sprintf("2606:4700:4700::%x", i)))
	}
	p.Refresh(context.Background())
	wire := query(t, "api.example.test.", 28)
	if m := unpack(t, p.Answer(wire, false)); !m.Truncated || len(m.Answers) != 0 {
		t.Fatal("UDP size limit not enforced", m)
	}
	if m := unpack(t, p.Answer(wire, true)); m.Truncated || len(m.Answers) != MaxAnswers {
		t.Fatal("TCP response incomplete", m)
	}
	if m := unpack(t, p.Answer(edns(wire, 0, nil), false)); m.Truncated || len(m.Answers) != MaxAnswers {
		t.Fatal("EDNS response incomplete", m)
	}
}

func startServer(t *testing.T, p *Proxy, host string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, u, l) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Error("DNS server did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return l.Addr().String(), stop
}
func tcpQuery(t *testing.T, conn net.Conn, wire []byte, split bool) dnsmessage.Message {
	t.Helper()
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
	framed := append(prefix[:], wire...)
	if split {
		for _, b := range framed {
			if _, err := conn.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		if _, err := conn.Write(framed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	return unpack(t, data)
}

func TestUDPAndTCPListenersIPv4IPv6(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			p, r := testProxy(t)
			addr, stop := startServer(t, p, host)
			u, err := net.Dial("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			u.SetDeadline(time.Now().Add(time.Second))
			wire := query(t, "api.example.test.", 1)
			if _, err = u.Write(wire); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1232)
			n, err := u.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if m := unpack(t, buf[:n]); m.RCode != 0 || len(m.Answers) != 1 {
				t.Fatal(m)
			}
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			if m := tcpQuery(t, conn, wire, true); m.RCode != 0 {
				t.Fatal(m)
			}
			if m := tcpQuery(t, conn, query(t, "ciphertext.api.example.test.", 16), false); m.RCode != dnsmessage.RCodeRefused {
				t.Fatal(m)
			}
			if m := tcpQuery(t, conn, wire, false); m.RCode != 0 {
				t.Fatal(m)
			}
			if r.count() != 1 {
				t.Fatal("listener relayed client data")
			}
			stop()
		})
	}
}

func TestTCPRejectsTLSHTTPAndOversizedFrames(t *testing.T) {
	p, r := testProxy(t)
	addr, _ := startServer(t, p, "127.0.0.1")
	for _, wire := range [][]byte{{0x16, 3, 3, 0, 10}, []byte("GET / HTTP/1.1\r\n\r\n"), {0, 0}, {2, 1}} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write(wire)
		var buf [1]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if n != 0 || err == nil {
			t.Fatal("opaque protocol accepted")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("opaque protocol was not rejected promptly")
		}
	}
	if r.count() != 1 {
		t.Fatal("opaque transport reached upstream")
	}
}

func TestSourceAdmissionAndRateBudget(t *testing.T) {
	p, _ := testProxy(t)
	p.clients = nil
	addr, _ := startServer(t, p, "127.0.0.1")
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	conn.Write(query(t, "api.example.test.", 1))
	var buf [512]byte
	if n, err := conn.Read(buf[:]); n != 0 || err == nil {
		t.Fatal("unapproved client received DNS")
	}
	p.rateMu.Lock()
	p.tokens = 0
	p.lastToken = time.Now()
	p.rateMu.Unlock()
	if p.takeToken() {
		t.Fatal("empty rate bucket allowed query")
	}
}

func FuzzClientWireNeverResolves(f *testing.F) {
	f.Add(query(f, "api.example.test.", 1))
	f.Add([]byte("TLS cipher"))
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, r := testProxy(t)
		for _, tcp := range []bool{false, true} {
			if out := p.Answer(wire, tcp); out != nil {
				m := unpack(t, out)
				if len(out) > 1232 || !m.Response {
					t.Fatal("unsafe response")
				}
			}
		}
		if r.count() != 1 {
			t.Fatal("client wire reached resolver")
		}
	})
}
