// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package egress supplies a deny-by-default HTTP transport for agent requests.
// Its exact-origin allowlist and pinned public-address dialer are independent of
// signatures. They do not replace an OS/network boundary against direct sockets.
package egress

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/ax/pkg/security/httpguard"
)

// Policy authorizes exact scheme, host, and effective-port origins. It is
// immutable after construction and safe for concurrent requests.
type Policy struct {
	origins   map[string]struct{}
	addresses map[string]struct{}
}

// NewPolicy accepts origin URLs without paths, queries, fragments, or userinfo.
// DNS names are not resolved until a permitted request opens a connection.
// Empty configuration denies every origin.
func NewPolicy(origins []string) (*Policy, error) {
	p := &Policy{origins: map[string]struct{}{}, addresses: map[string]struct{}{}}
	for _, raw := range origins {
		origin, address, err := canonicalOrigin(raw, true)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed origin: %w", err)
		}
		p.origins[origin] = struct{}{}
		p.addresses[address] = struct{}{}
	}
	return p, nil
}

// CheckURL validates request syntax and exact-origin authorization without DNS.
// A successful check is not an IP-address authorization; the transport performs
// the latter on every new connection before dialing any address.
func (p *Policy) CheckURL(rawURL string) error {
	origin, _, err := canonicalOrigin(rawURL, false)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("outbound origin is not allowed")
	}
	if _, ok := p.origins[origin]; !ok {
		return fmt.Errorf("outbound origin %s is not allowed", origin)
	}
	return nil
}

func canonicalOrigin(raw string, originOnly bool) (string, string, error) {
	if err := httpguard.ValidateURL(raw); err != nil {
		return "", "", err
	}
	if raw == "" || len(raw) > 16<<10 {
		return "", "", fmt.Errorf("invalid URL length")
	}
	for _, c := range raw {
		if c <= 32 || c == 127 || c == '#' {
			return "", "", fmt.Errorf("URL contains a control, whitespace, or fragment")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("an absolute HTTP(S) URL without userinfo is required")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("only HTTP(S) origins are allowed")
	}
	if originOnly && (u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery) {
		return "", "", fmt.Errorf("allowed origins cannot contain a path or query")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "%\\") {
		return "", "", fmt.Errorf("invalid origin hostname")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if strings.HasPrefix(u.Host, "[") != ip.Is6() {
			return "", "", fmt.Errorf("invalid IP authority brackets")
		}
		if !publicAddress(ip) {
			return "", "", fmt.Errorf("origin IP is not public")
		}
		host = ip.String()
	} else if strings.HasPrefix(u.Host, "[") || !validDNSName(host) {
		return "", "", fmt.Errorf("origin hostname must be an ASCII fully qualified DNS name")
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", "", fmt.Errorf("empty origin port")
		}
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	} else {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", "", fmt.Errorf("invalid origin port")
		}
		port = strconv.Itoa(n)
	}
	address := net.JoinHostPort(host, port)
	return scheme + "://" + address, address, nil
}

func validDNSName(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, suffix := range []string{"localhost", "local", "internal", "home.arpa", "onion"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return false
		}
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// Reject legacy dotted/octal/integer numeric host representations. A real
	// address must parse through netip rather than the platform resolver.
	last := labels[len(labels)-1]
	for _, c := range last {
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// Conservatively exclude every IANA special-purpose assignment, including
// assignments marked globally reachable, plus cloud platform service IPs.
// Sources (checked 2026-09-26):
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

var ipv6Global = netip.MustParsePrefix("2000::/3")

// IsPublicAddress excludes non-global and special-purpose destinations using
// the same policy for HTTP dialing and the sandbox DNS proxy's default answers.
func IsPublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.Is6() && !ipv6Global.Contains(ip) {
		return false
	}
	for _, prefix := range excluded {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func publicAddress(ip netip.Addr) bool { return IsPublicAddress(ip) }
