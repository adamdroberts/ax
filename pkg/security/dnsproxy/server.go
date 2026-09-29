// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ListenAndServe owns UDP and TCP listeners on the same numeric endpoint. The
// caller runs RunRefresh separately, so request timing never schedules lookups.
func (p *Proxy) ListenAndServe(ctx context.Context, address string) error {
	addr, err := netip.ParseAddrPort(address)
	if err != nil || addr.Addr().Zone() != "" || addr.Addr().Is4In6() || addr.Addr().IsMulticast() {
		return fmt.Errorf("listen address must be a numeric IPv4 or IPv6 IP:port")
	}
	var lc net.ListenConfig
	tcp, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	udp, err := lc.ListenPacket(ctx, "udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		return err
	}
	return p.Serve(ctx, udp, tcp)
}

// Serve owns its listeners. Each transport has reserved worker capacity within
// the aggregate limit, with shared source admission and rate budget.
// TCP uses RFC 1035 length framing and supports
// sequential/pipelined queries with bounded idle and total connection lifetimes.
func (p *Proxy) Serve(ctx context.Context, udp net.PacketConn, tcp net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	stop := func() { once.Do(func() { udp.Close(); tcp.Close() }) }
	defer stop()
	stopContext := context.AfterFunc(ctx, stop)
	defer stopContext()
	udpWorkers := make(chan struct{}, MaxUDPWorkers)
	tcpWorkers := make(chan struct{}, MaxTCPConnections)
	var active sync.WaitGroup
	errorsCh := make(chan error, 2)
	active.Go(func() {
		buf := make([]byte, MaxQueryBytes+1)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				errorsCh <- err
				return
			}
			if !p.clientAllowed(addr) || !p.takeToken() {
				p.denied.Add(1)
				continue
			}
			select {
			case udpWorkers <- struct{}{}:
			default:
				p.denied.Add(1)
				continue
			}
			data := append([]byte(nil), buf[:n]...)
			active.Go(func() {
				defer func() { <-udpWorkers }()
				if response := p.Answer(data, false); response != nil {
					_, _ = udp.WriteTo(response, addr)
				}
			})
		}
	})
	active.Go(func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				errorsCh <- err
				return
			}
			if !p.clientAllowed(conn.RemoteAddr()) {
				p.denied.Add(1)
				conn.Close()
				continue
			}
			select {
			case tcpWorkers <- struct{}{}:
			default:
				p.denied.Add(1)
				conn.Close()
				continue
			}
			active.Go(func() {
				defer func() { <-tcpWorkers }()
				defer conn.Close()
				cancelConn := context.AfterFunc(ctx, func() { conn.Close() })
				defer cancelConn()
				p.serveTCP(conn)
			})
		}
	})
	var result error
	select {
	case <-ctx.Done():
	case result = <-errorsCh:
	}
	cancel()
	stop()
	active.Wait()
	if errors.Is(result, net.ErrClosed) {
		return nil
	}
	return result
}

func (p *Proxy) serveTCP(conn net.Conn) {
	end := time.Now().Add(30 * time.Second)
	for i := 0; i < 32; i++ {
		deadline := time.Now().Add(3 * time.Second)
		if end.Before(deadline) {
			deadline = end
		}
		if conn.SetDeadline(deadline) != nil {
			return
		}
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if n < 12 || n > MaxQueryBytes || !p.takeToken() {
			p.denied.Add(1)
			return
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}
		response := p.Answer(data, true)
		if response == nil {
			return
		}
		binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
		buffers := net.Buffers{prefix[:], response}
		if _, err := buffers.WriteTo(conn); err != nil {
			return
		}
	}
}
