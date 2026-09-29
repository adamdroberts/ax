package dnsproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These adapters exercise Serve's actual admission and worker lifecycle without
// opening interfaces. net.Pipe retains real blocking I/O and deadline behavior.
type capacityConn struct {
	net.Conn
	peer   net.Addr
	ready  chan struct{}
	once   sync.Once
	closed atomic.Bool
}

func (c *capacityConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.ready) })
	return c.Conn.Read(p)
}
func (c *capacityConn) Close() error {
	c.closed.Store(true)
	c.once.Do(func() { close(c.ready) })
	return c.Conn.Close()
}
func (c *capacityConn) RemoteAddr() net.Addr { return c.peer }

type capacityListener struct {
	input chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *capacityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.input:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *capacityListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*capacityListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353} }

type capacityPacketConn struct {
	input       chan []byte
	output      chan []byte
	reading     chan struct{}
	done        chan struct{}
	once        sync.Once
	peer        net.Addr
	blockWrites bool
}

func (c *capacityPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	select {
	case c.reading <- struct{}{}:
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
	select {
	case packet := <-c.input:
		return copy(data, packet), c.peer, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}
func (c *capacityPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	if c.blockWrites {
		<-c.done
		return 0, net.ErrClosed
	}
	select {
	case c.output <- append([]byte(nil), data...):
		return len(data), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *capacityPacketConn) Close() error              { c.once.Do(func() { close(c.done) }); return nil }
func (c *capacityPacketConn) LocalAddr() net.Addr       { return c.peer }
func (*capacityPacketConn) SetDeadline(time.Time) error { return nil }
func (*capacityPacketConn) SetReadDeadline(time.Time) error {
	return nil
}
func (*capacityPacketConn) SetWriteDeadline(time.Time) error { return nil }

func capacityWait(t *testing.T, ready <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func TestDNSTransportWorkerIsolation(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, pressure := range []string{"idle-tcp", "blocked-udp-writes"} {
			t.Run(family+"/"+pressure, func(t *testing.T) {
				p, resolver := testProxy(t)
				ip := net.ParseIP("127.0.0.1")
				if family == "ipv6" {
					ip = net.ParseIP("::1")
				}
				udp := &capacityPacketConn{input: make(chan []byte), output: make(chan []byte, 1),
					reading: make(chan struct{}, 1), done: make(chan struct{}),
					peer: &net.UDPAddr{IP: ip, Port: 44000}, blockWrites: pressure == "blocked-udp-writes"}
				tcp := &capacityListener{input: make(chan net.Conn), done: make(chan struct{})}
				ctx, cancel := context.WithCancel(context.Background())
				stopped := make(chan error, 1)
				go func() { stopped <- p.Serve(ctx, udp, tcp) }()
				t.Cleanup(func() {
					cancel()
					select {
					case err := <-stopped:
						if err != nil {
							t.Error("shutdown failed", err)
						}
					case <-time.After(5 * time.Second):
						t.Error("saturated DNS server did not stop")
					}
					if resolver.count() != 1 {
						t.Error("client pressure caused an upstream lookup")
					}
				})
				capacityWait(t, udp.reading, "UDP listener did not start")
				openTCP := func() (*capacityConn, net.Conn) {
					client, server := net.Pipe()
					t.Cleanup(func() { client.Close() })
					tracked := &capacityConn{Conn: server, peer: &net.TCPAddr{IP: ip, Port: 44001}, ready: make(chan struct{})}
					select {
					case tcp.input <- tracked:
					case <-time.After(2 * time.Second):
						t.Fatal("TCP listener did not accept")
					}
					capacityWait(t, tracked.ready, "TCP connection was neither handled nor rejected")
					return tracked, client
				}
				request := query(t, "api.example.test.", dnsmessage.TypeA)
				sendUDP := func() {
					select {
					case udp.input <- request:
					case <-time.After(2 * time.Second):
						t.Fatal("UDP listener did not receive")
					}
					// The next ReadFrom starts only after the preceding datagram
					// has acquired a worker or been denied. No scheduling sleep.
					capacityWait(t, udp.reading, "UDP admission did not complete")
				}
				if pressure == "idle-tcp" {
					var connections []*capacityConn
					for i := 0; i < MaxWorkers; i++ {
						server, _ := openTCP()
						connections = append(connections, server)
					}
					denied := p.Stats().Denied
					sendUDP()
					if p.Stats().Denied != denied {
						t.Fatal("idle TCP connections exhausted the UDP worker capacity")
					}
					select {
					case answer := <-udp.output:
						if m := unpack(t, answer); m.RCode != 0 || len(m.Answers) != 1 {
							t.Fatal("UDP cache reply was not preserved")
						}
					case <-time.After(2 * time.Second):
						t.Fatal("UDP query received no reply under idle TCP pressure")
					}
					closed := 0
					for _, conn := range connections {
						if conn.closed.Load() {
							closed++
						}
					}
					if closed != MaxWorkers/2 {
						t.Fatalf("closed %d excess TCP connections, want %d", closed, MaxWorkers/2)
					}
					return
				}
				for i := 0; i < MaxWorkers; i++ {
					if i%64 == 0 {
						// Hold the independent rate budget constant to isolate
						// worker admission; no public traffic or elapsed-time test.
						p.rateMu.Lock()
						p.tokens, p.lastToken = 100, time.Now()
						p.rateMu.Unlock()
					}
					sendUDP()
				}
				p.rateMu.Lock()
				p.tokens, p.lastToken = 100, time.Now()
				p.rateMu.Unlock()
				server, client := openTCP()
				if server.closed.Load() {
					t.Fatal("blocked UDP replies exhausted the TCP worker capacity")
				}
				client.SetDeadline(time.Now().Add(2 * time.Second))
				var prefix [2]byte
				binary.BigEndian.PutUint16(prefix[:], uint16(len(request)))
				buffers := net.Buffers{prefix[:], request}
				if _, err := buffers.WriteTo(client); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, prefix[:]); err != nil {
					t.Fatal(err)
				}
				answer := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(client, answer); err != nil {
					t.Fatal(err)
				}
				if m := unpack(t, answer); m.RCode != 0 || len(m.Answers) != 1 {
					t.Fatal("TCP cache reply was not preserved")
				}
			})
		}
	}
}
