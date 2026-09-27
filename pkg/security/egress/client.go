// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/ax/pkg/security/httpguard"
)

const (
	// The proxy request context supplies its configured 1..120 second limit.
	// This independent ceiling also bounds direct users of this client.
	RequestTimeout = 120 * time.Second
	ConnectTimeout = 10 * time.Second
)

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

type requestMethodKey struct{}

// NewClient creates an isolated HTTP/1.1 client. It has no environment proxy,
// cookie jar, automatic redirects/decompression, or connection reuse. TLS uses
// the system trust roots and the original hostname for certificate verification.
func NewClient(origins []string) (*http.Client, error) {
	p, err := NewPolicy(origins)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: ConnectTimeout, KeepAlive: -1}
	return newClient(p, net.DefaultResolver, dialer.DialContext), nil
}

func newClient(p *Policy, dns resolver, dial dialFunc) *http.Client {
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	pinned := p.pinnedDialer(dns, dial)
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:    ConnectTimeout,
		ResponseHeaderTimeout:  15 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        4,
		ForceAttemptHTTP2:      false,
		Protocols:              protocols,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := pinned(ctx, network, address)
		if err != nil {
			return nil, err
		}
		method, _ := ctx.Value(requestMethodKey{}).(string)
		return newResponseConn(conn, method), nil
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := pinned(ctx, network, address)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			conn.Close()
			return nil, err
		}
		config := transport.TLSClientConfig.Clone()
		config.ServerName = host
		tlsConn := tls.Client(conn, config)
		handshakeCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("outbound TLS handshake failed: %w", err)
		}
		if protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != "http/1.1" {
			tlsConn.Close()
			return nil, fmt.Errorf("unsupported outbound TLS application protocol")
		}
		// The wire guard must sit ABOVE TLS so encrypted and plaintext responses
		// receive the same checks before net/http normalizes their headers.
		method, _ := ctx.Value(requestMethodKey{}).(string)
		return newResponseConn(tlsConn, method), nil
	}
	return &http.Client{
		Transport:     &guardedTransport{policy: p, base: transport},
		Timeout:       RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Jar:           nil,
	}
}

func (p *Policy) pinnedDialer(dns resolver, dial dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unsupported outbound network")
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid outbound address")
		}
		host = strings.ToLower(host)
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.String()
		}
		if _, ok := p.addresses[net.JoinHostPort(host, port)]; !ok {
			return nil, fmt.Errorf("outbound address is not allowed")
		}
		ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip}
		} else {
			// Resolve once, validate the ENTIRE answer set before the first dial,
			// then pass only numeric IPs to the socket dialer (no second lookup).
			// A trailing DNS root dot prevents resolver search domains from
			// silently expanding the explicitly approved hostname.
			ips, err = dns.LookupNetIP(ctx, "ip", host+".")
			if err != nil {
				return nil, fmt.Errorf("outbound DNS lookup failed: %w", err)
			}
		}
		if len(ips) == 0 || len(ips) > 64 {
			return nil, fmt.Errorf("outbound DNS result count is invalid")
		}
		for _, ip := range ips {
			if !publicAddress(ip) {
				return nil, fmt.Errorf("outbound DNS contains a nonpublic or special address")
			}
		}
		var lastErr error
		for _, ip := range ips {
			family := "tcp4"
			if ip.Is6() {
				family = "tcp6"
			}
			conn, err := dial(ctx, family, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, fmt.Errorf("outbound connection failed: %w", lastErr)
	}
}

type guardedTransport struct {
	policy *Policy
	base   *http.Transport
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deny := func(err error) (*http.Response, error) {
		if req != nil && req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	if req == nil || req.URL == nil {
		return deny(fmt.Errorf("invalid outbound request"))
	}
	if err := t.policy.CheckURL(req.URL.String()); err != nil {
		return deny(err)
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return deny(fmt.Errorf("outbound Host override is not allowed"))
	}
	if req.Method == "CONNECT" || req.Header.Get("Upgrade") != "" || len(req.TransferEncoding) > 0 || len(req.Trailer) > 0 {
		return deny(fmt.Errorf("outbound tunnels and upgrades are not allowed"))
	}
	if err := checkRequestHeaders(req.Header); err != nil {
		return deny(err)
	}
	cloned := req.Clone(context.WithValue(req.Context(), requestMethodKey{}, req.Method))
	cloned.URL.Scheme = strings.ToLower(cloned.URL.Scheme)
	cloned.Host = cloned.URL.Host
	cloned.Header.Set("Accept-Encoding", "identity")
	cloned.Close = true
	resp, err := t.base.RoundTrip(cloned)
	if err != nil {
		return nil, err
	}
	if resp.Request == nil {
		resp.Request = cloned
	}
	if err := CheckResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body = &guardedBody{ReadCloser: resp.Body, response: resp, remaining: MaxResponseBodyBytes}
	return resp, nil
}

func (t *guardedTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

func checkRequestHeaders(headers http.Header) error {
	count, size := 0, 0
	seen := map[string]bool{}
	for key, values := range headers {
		name := strings.ToLower(key)
		if !headerToken(key) || seen[name] {
			return fmt.Errorf("invalid or duplicate outbound header name")
		}
		seen[name] = true
		switch name {
		case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "proxy-authorization", "upgrade", "trailer", "te", "expect":
			return fmt.Errorf("outbound framing and hop-by-hop headers are transport-managed")
		case "content-encoding":
			if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "identity") {
				return fmt.Errorf("encoded outbound bodies are not allowed")
			}
		}
		for _, value := range values {
			if err := httpguard.ValidateHeader(key, value); err != nil {
				return err
			}
			count++
			size += len(key) + len(value) + 4
			for _, c := range value {
				if c < 32 && c != '\t' || c == 127 {
					return fmt.Errorf("invalid outbound header value")
				}
			}
		}
	}
	if count > MaxResponseHeaders || size > MaxResponseHeaderBytes {
		return fmt.Errorf("outbound headers exceed limits")
	}
	return nil
}
