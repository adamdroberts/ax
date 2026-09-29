// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package dnsproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type pinnedResolver struct{ address string }

// PinnedResolver has no fallback to system DNS, search suffixes or another IP.
// A dedicated validating resolver belongs at this trusted numeric endpoint.
func PinnedResolver(upstream string) (Resolver, error) {
	addr, err := netip.ParseAddrPort(upstream)
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Addr().Zone() != "" || addr.Addr().Is4In6() {
		return nil, fmt.Errorf("upstream must be an explicit unicast IP:port")
	}
	return &pinnedResolver{addr.String()}, nil
}

func (r *pinnedResolver) Resolve(ctx context.Context, name string) (Resolution, error) {
	var result Resolution
	result.TTL = 24 * time.Hour
	// Always ask both types from the approved-name refresh, independently of
	// the types clients request. Fail the whole answer set on either error.
	var failure error
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addresses, ttl, err := r.lookup(ctx, name, kind)
		if err != nil {
			failure = err
			continue
		}
		result.Addresses = append(result.Addresses, addresses...)
		if len(addresses) > 0 {
			result.TTL = min(result.TTL, ttl)
		}
	}
	return result, failure
}

func (r *pinnedResolver) lookup(ctx context.Context, name string, kind dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, 0, err
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(random[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: kind, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return nil, 0, err
	}
	for _, network := range []string{"udp", "tcp"} {
		data, err := r.exchange(ctx, network, wire)
		if err != nil {
			return nil, 0, err
		}
		if !exactEnvelope(data) {
			return nil, 0, fmt.Errorf("upstream DNS framing is invalid")
		}
		var response dnsmessage.Message
		if err := response.Unpack(data); err != nil {
			return nil, 0, fmt.Errorf("malformed upstream response")
		}
		if !response.Response || response.ID != query.ID || response.OpCode != 0 || response.RCode != dnsmessage.RCodeSuccess || len(response.Questions) != 1 ||
			!strings.EqualFold(response.Questions[0].Name.String(), name) || response.Questions[0].Type != kind || response.Questions[0].Class != dnsmessage.ClassINET {
			return nil, 0, fmt.Errorf("upstream response does not match query")
		}
		if response.Truncated && network == "udp" {
			continue
		}
		if response.Truncated {
			return nil, 0, fmt.Errorf("truncated upstream TCP response")
		}
		return extractAddresses(response, name, kind)
	}
	return nil, 0, fmt.Errorf("incomplete upstream exchange")
}

func (r *pinnedResolver) exchange(ctx context.Context, network string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, r.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if network == "udp" {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		// No EDNS was advertised; RFC 1035's 512-byte UDP limit applies.
		buf := make([]byte, 513)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n > 512 {
			return nil, fmt.Errorf("upstream DNS response exceeds budget")
		}
		return buf[:n], nil
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
	buffers := net.Buffers{prefix[:], query}
	if _, err := buffers.WriteTo(conn); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n < 12 || n > 4096 {
		return nil, fmt.Errorf("upstream DNS response exceeds budget")
	}
	data := make([]byte, n)
	_, err = io.ReadFull(conn, data)
	return data, err
}

func extractAddresses(message dnsmessage.Message, name string, kind dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	current := strings.ToLower(name)
	ttl := 24 * time.Hour
	seen := map[string]bool{}
	for depth := 0; depth <= 8; depth++ {
		if seen[current] {
			return nil, 0, fmt.Errorf("upstream CNAME loop")
		}
		seen[current] = true
		var next string
		var addresses []netip.Addr
		var otherData bool
		for _, rr := range message.Answers {
			if !strings.EqualFold(rr.Header.Name.String(), current) {
				continue
			}
			if rr.Header.Class != dnsmessage.ClassINET {
				return nil, 0, fmt.Errorf("unexpected upstream DNS class")
			}
			recordTTL := time.Duration(rr.Header.TTL) * time.Second
			// RFC 2181 section 8: a received TTL with its high bit set is zero.
			if rr.Header.TTL&0x80000000 != 0 {
				recordTTL = 0
			}
			switch body := rr.Body.(type) {
			case *dnsmessage.CNAMEResource:
				target, err := canonicalName(body.CNAME.String())
				if err != nil || next != "" && next != target {
					return nil, 0, fmt.Errorf("ambiguous upstream CNAME")
				}
				next = target
				ttl = min(ttl, recordTTL)
			case *dnsmessage.AResource:
				otherData = true
				if kind == dnsmessage.TypeA {
					addresses = append(addresses, netip.AddrFrom4(body.A))
					ttl = min(ttl, recordTTL)
				}
			case *dnsmessage.AAAAResource:
				otherData = true
				if kind == dnsmessage.TypeAAAA {
					addresses = append(addresses, netip.AddrFrom16(body.AAAA))
					ttl = min(ttl, recordTTL)
				}
			default:
				// RFC 4035 section 2.5 permits only KEY, RRSIG and NSEC
				// alongside CNAME. Check all other data independently of
				// the requested address family and record order.
				if rr.Header.Type != 25 && rr.Header.Type != 46 && rr.Header.Type != 47 {
					otherData = true
				}
			}
		}
		if next == "" {
			return addresses, ttl, nil
		}
		if otherData {
			return nil, 0, fmt.Errorf("upstream CNAME owner has conflicting data")
		}
		current = next
	}
	return nil, 0, fmt.Errorf("upstream CNAME chain exceeds budget")
}
