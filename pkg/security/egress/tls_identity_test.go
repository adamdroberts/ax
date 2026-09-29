package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSharedTLSServiceIdentity(t *testing.T) {
	const directory = "testdata/tls-identity"
	data, err := os.ReadFile(filepath.Join(directory, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		TLSVersions []string `json:"tls_versions"`
		Cases       []struct {
			Name, Host, Certificate string
			Trusted, Accepted       bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		for _, version := range corpus.TLSVersions {
			t.Run(tc.Name+"/"+version, func(t *testing.T) {
				t.Parallel()
				cert, err := tls.LoadX509KeyPair(filepath.Join(directory, tc.Certificate), filepath.Join(directory, "server-key.pem"))
				if err != nil {
					t.Fatal(err)
				}
				protocol := map[string]uint16{"TLSv1.2": tls.VersionTLS12, "TLSv1.3": tls.VersionTLS13}[version]
				if protocol == 0 {
					t.Fatal("invalid fixture protocol")
				}
				authority, dialIP, sni := tc.Host, "8.8.8.8", tc.Host
				if ip := net.ParseIP(tc.Host); ip != nil {
					dialIP, sni = ip.String(), ""
					if ip.To4() == nil {
						authority = "[" + tc.Host + "]"
					}
				}
				origin := "https://" + authority
				type observation struct {
					hello, request        bool
					sni, host, auth, alpn string
				}
				done, dialed := make(chan observation, 1), make(chan string, 1)
				client := newClient(mustPolicy(t, origin), fakeDNS("8.8.8.8"), func(_ context.Context, _, address string) (net.Conn, error) {
					dialed <- address
					left, right := net.Pipe()
					go func() {
						var got observation
						defer func() { right.Close(); done <- got }()
						right.SetDeadline(time.Now().Add(3 * time.Second))
						conn := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: protocol, MaxVersion: protocol, NextProtos: []string{"h2", "http/1.1"},
							GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
								got.hello, got.sni = true, hello.ServerName
								return nil, nil
							}})
						if conn.Handshake() != nil {
							return
						}
						got.alpn = conn.ConnectionState().NegotiatedProtocol
						req, err := http.ReadRequest(bufio.NewReader(conn))
						if err != nil {
							return
						}
						got.request, got.host, got.auth = true, req.Host, req.Header.Get("Authorization")
						req.Body.Close()
						io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					}()
					return left, nil
				})
				roots := x509.NewCertPool()
				if tc.Trusted && !roots.AppendCertsFromPEM(ca) {
					t.Fatal("fixture CA did not load")
				}
				client.Transport.(*guardedTransport).base.TLSClientConfig.RootCAs = roots // Isolated test-only trust.
				req, _ := http.NewRequest("GET", origin+"/identity", nil)
				req.Header.Set("Authorization", "Bearer tls-identity-fixture")
				resp, err := client.Do(req)
				var body []byte
				if resp != nil {
					body, err = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				var got observation
				select {
				case got = <-done:
				case <-time.After(4 * time.Second):
					t.Fatal("TLS fixture worker did not finish")
				}
				select {
				case address := <-dialed:
					if address != net.JoinHostPort(dialIP, "443") {
						t.Fatalf("dial was not pinned: %s", address)
					}
				default:
					t.Fatal("TLS fixture was not reached")
				}
				if !got.hello || got.sni != sni {
					t.Fatalf("incorrect SNI: %+v", got)
				}
				if (err == nil) != tc.Accepted {
					t.Fatalf("accepted=%v want=%v error=%v request_sent=%v", err == nil, tc.Accepted, err, got.request)
				}
				var verificationError *tls.CertificateVerificationError
				if !tc.Accepted && !errors.As(err, &verificationError) {
					t.Fatalf("expected certificate verification failure, got %v", err)
				}
				if got.request != tc.Accepted {
					t.Fatalf("HTTP request reached unaccepted TLS identity: %+v", got)
				}
				if tc.Accepted && (string(body) != "ok" || got.host != authority || got.auth != "Bearer tls-identity-fixture" || got.alpn != "http/1.1") {
					t.Fatalf("authorized HTTP exchange changed: body=%q observation=%+v", body, got)
				}
				if !tc.Accepted && strings.Contains(string(body), "ok") {
					t.Fatal("rejected TLS response delivered content")
				}
			})
		}
	}
}
