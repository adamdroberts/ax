package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   []string
	err     error
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+":"+host)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.answers) == 0 {
		return nil, nil
	}
	n := len(f.calls) - 1
	if n >= len(f.answers) {
		n = len(f.answers) - 1
	}
	return f.answers[n], nil
}

func mustPolicy(t *testing.T, origins ...string) *Policy {
	t.Helper()
	p, err := NewPolicy(origins)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeDNS(addresses ...string) *fakeResolver {
	ips := make([]netip.Addr, len(addresses))
	for i, raw := range addresses {
		ips[i] = netip.MustParseAddr(raw)
	}
	return &fakeResolver{answers: [][]netip.Addr{ips}}
}

func TestAllowlistDeniesBeforeDNSOrDial(t *testing.T) {
	for _, allowed := range [][]string{nil, {"https://api.example.com"}} {
		p := mustPolicy(t, allowed...)
		dns := fakeDNS("8.8.8.8")
		var dials atomic.Int32
		client := newClient(p, dns, func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		})
		if _, err := client.Get("https://unapproved.example.com/leak"); err == nil {
			t.Fatal("unapproved request accepted")
		}
		if len(dns.calls) != 0 || dials.Load() != 0 {
			t.Fatal("unapproved origin caused DNS or network traffic")
		}
	}
}

func TestDNSAnswerSetMustBeEntirelyPublic(t *testing.T) {
	for _, addresses := range [][]string{
		{}, {"127.0.0.1"}, {"8.8.8.8", "10.0.0.1"}, {"8.8.8.8", "::ffff:127.0.0.1"}, {"2606:4700:4700::1111", "fd00::1"}, {"8.8.8.8", "168.63.129.16"}, {"8.8.8.8", "2001:db8::1"},
	} {
		dns := fakeDNS(addresses...)
		p := mustPolicy(t, "https://api.example.com")
		var dials atomic.Int32
		dial := p.pinnedDialer(dns, func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		})
		if _, err := dial(context.Background(), "tcp", "api.example.com:443"); err == nil {
			t.Errorf("accepted answers %v", addresses)
		}
		if dials.Load() != 0 || len(dns.calls) != 1 {
			t.Errorf("partial answer validation for %v: DNS=%d dials=%d", addresses, len(dns.calls), dials.Load())
		}
	}
}

func TestDNSIsResolvedOnceThenNumericIPsArePinned(t *testing.T) {
	p := mustPolicy(t, "https://api.example.com")
	dns := &fakeResolver{answers: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")}, {netip.MustParseAddr("127.0.0.1")}}}
	var dialed []string
	dial := p.pinnedDialer(dns, func(_ context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, network+":"+addr)
		if len(dialed) == 1 {
			return nil, errors.New("first public address unreachable")
		}
		client, server := net.Pipe()
		server.Close()
		return client, nil
	})
	conn, err := dial(context.Background(), "tcp", "api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(dns.calls) != 1 || dns.calls[0] != "ip:api.example.com." || strings.Join(dialed, ",") != "tcp4:8.8.8.8:443,tcp6:[2606:4700:4700::1111]:443" {
		t.Fatalf("not pinned: lookups=%v dials=%v", dns.calls, dialed)
	}
	if _, err := dial(context.Background(), "tcp", "api.example.com:443"); err == nil {
		t.Fatal("second connection accepted rebound private address")
	}
	if len(dialed) != 2 || len(dns.calls) != 2 {
		t.Fatal("rebinding caused a private dial or stale DNS reuse")
	}
}

func pipeResponse(wire string, onRequest func(*http.Request)) dialFunc {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.SetDeadline(time.Now().Add(5 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			if req.Body != nil {
				io.Copy(io.Discard, req.Body)
				req.Body.Close()
			}
			if onRequest != nil {
				onRequest(req)
			}
			io.WriteString(server, wire)
		}()
		return client, nil
	}
}

func TestClientHasNoRedirectCookieProxyOrConnectionReuse(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	p := mustPolicy(t, "http://api.example.com", "http://other.example.com")
	dns := fakeDNS("8.8.8.8")
	var dials atomic.Int32
	requests := make(chan *http.Request, 2)
	dial := pipeResponse("HTTP/1.1 302 Found\r\nLocation: http://other.example.com/leak\r\nSet-Cookie: session=ambient\r\nContent-Length: 0\r\n\r\n", func(r *http.Request) { requests <- r })
	client := newClient(p, dns, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp4" || addr != "8.8.8.8:80" {
			t.Errorf("unvetted dial %s %s", network, addr)
		}
		return dial(ctx, network, addr)
	})
	for i := 0; i < 2; i++ {
		resp, err := client.Get("http://api.example.com/path")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			t.Fatal("redirect was followed")
		}
		req := <-requests
		if req.Host != "api.example.com" || req.Proto != "HTTP/1.1" || req.Header.Get("Accept-Encoding") != "identity" || req.Header.Get("Cookie") != "" {
			t.Fatalf("unexpected wire request: %+v", req)
		}
	}
	base := client.Transport.(*guardedTransport).base
	if dials.Load() != 2 || len(dns.calls) != 2 || client.Jar != nil || base.Proxy != nil || !base.DisableCompression || !base.DisableKeepAlives || base.Protocols.HTTP2() || base.TLSClientConfig.InsecureSkipVerify || base.TLSClientConfig.RootCAs != nil {
		t.Fatal("transport security settings changed")
	}
}

func TestClientRejectsHostAndFramingOverridesBeforeDNS(t *testing.T) {
	for _, header := range []string{"Host", "host", "Content-Length", "Transfer-Encoding", "Connection", "proxy-authorization", "Upgrade", "Trailer", "TE", "Expect", "Bad Header"} {
		dns := fakeDNS("8.8.8.8")
		client := newClient(mustPolicy(t, "http://api.example.com"), dns, nil)
		req, _ := http.NewRequest("GET", "http://api.example.com", nil)
		req.Header[header] = []string{"x"}
		if _, err := client.Do(req); err == nil || len(dns.calls) != 0 {
			t.Errorf("header %s was not rejected before DNS", header)
		}
	}
	dns := fakeDNS("8.8.8.8")
	client := newClient(mustPolicy(t, "http://api.example.com"), dns, nil)
	req, _ := http.NewRequest("GET", "http://api.example.com", nil)
	req.Host = "attacker.example.com"
	if _, err := client.Do(req); err == nil || len(dns.calls) != 0 {
		t.Fatal("Host override was not rejected")
	}
}

func testCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestTLSPinningRetainsServerNameAndCertificateVerification(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		for _, certificateName := range []string{"api.example.com", "wrong.example.com"} {
			cert, roots := testCertificate(t, certificateName)
			serverNames := make(chan string, 1)
			client := newClient(mustPolicy(t, "https://api.example.com"), fakeDNS("8.8.8.8"), func(_ context.Context, _, addr string) (net.Conn, error) {
				if addr != "8.8.8.8:443" {
					t.Errorf("TLS dial used hostname: %s", addr)
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					server.SetDeadline(time.Now().Add(5 * time.Second))
					conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						serverNames <- hello.ServerName
						return nil, nil
					}})
					if err := conn.Handshake(); err != nil {
						return
					}
					if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
						t.Error("HTTP/2 negotiated")
					}
					if _, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
						io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					}
				}()
				return client, nil
			})
			if trusted {
				// Test-only trust root: production NewClient always uses OS roots.
				client.Transport.(*guardedTransport).base.TLSClientConfig.RootCAs = roots
			}
			resp, err := client.Get("https://api.example.com/path")
			wantSuccess := trusted && certificateName == "api.example.com"
			if (err == nil) != wantSuccess {
				t.Fatalf("trusted=%v cert=%s err=%v", trusted, certificateName, err)
			}
			if resp != nil {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "ok" {
					t.Fatalf("TLS response failed: %q %v", body, err)
				}
			}
			if got := <-serverNames; got != "api.example.com" {
				t.Fatalf("SNI changed to dial IP: %q", got)
			}
		}
	}
}
