// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package dnsproxy provides a finite DNS namespace for an agent sandbox.
// Client packets never become upstream packets or trigger upstream lookups.
// Only administrator-configured names are refreshed on an independent schedule.
package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/ax/pkg/security/egress"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	MaxNames      = 256
	MaxQueryBytes = 512
	MaxAnswers    = 32
	MaxWorkers    = 128
)

// Resolver is a trusted dependency. It receives only canonical configured names,
// never a name, record type, ID, flags, or EDNS data copied from an agent packet.
type Resolver interface {
	Resolve(context.Context, string) (Resolution, error)
}

type Resolution struct {
	Addresses []netip.Addr
	TTL       time.Duration
}

type Config struct {
	AllowedNames []string
	ClientNets   []netip.Prefix
	// Empty means globally routable public addresses only. When set, EVERY
	// returned address must be in these explicit administrator-owned ranges.
	AnswerNets      []netip.Prefix
	RefreshInterval time.Duration
	LookupTimeout   time.Duration
}

type entry struct {
	addresses []netip.Addr
	expires   time.Time
	code      dnsmessage.RCode
}

type Proxy struct {
	names                               []string
	allowed                             map[string]struct{}
	clients, answers                    []netip.Prefix
	resolver                            Resolver
	interval, timeout                   time.Duration
	mu                                  sync.RWMutex
	cache                               map[string]entry
	refreshMu                           sync.Mutex
	rateMu                              sync.Mutex
	tokens                              float64
	lastToken                           time.Time
	queries, denied, upstream, failures atomic.Uint64
}

type Stats struct {
	Queries         uint64 `json:"queries"`
	Denied          uint64 `json:"denied"`
	UpstreamLookups uint64 `json:"upstream_lookups"`
	RefreshFailures uint64 `json:"refresh_failures"`
}

func New(cfg Config, resolver Resolver) (*Proxy, error) {
	if len(cfg.AllowedNames) > MaxNames || len(cfg.ClientNets) > MaxNames || len(cfg.AnswerNets) > MaxNames {
		return nil, fmt.Errorf("DNS configuration exceeds %d entries", MaxNames)
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = time.Minute
	}
	if cfg.LookupTimeout == 0 {
		cfg.LookupTimeout = 3 * time.Second
	}
	if cfg.RefreshInterval < 10*time.Second || cfg.RefreshInterval > 5*time.Minute || cfg.LookupTimeout < time.Millisecond || cfg.LookupTimeout > 10*time.Second {
		return nil, fmt.Errorf("refresh must be 10s..5m and lookup timeout 1ms..10s")
	}
	p := &Proxy{allowed: map[string]struct{}{}, cache: map[string]entry{}, resolver: resolver,
		interval: cfg.RefreshInterval, timeout: cfg.LookupTimeout,
		tokens: 100, lastToken: time.Now()}
	for _, name := range cfg.AllowedNames {
		name, err := canonicalName(name)
		if err != nil {
			return nil, err
		}
		if _, exists := p.allowed[name]; exists {
			return nil, fmt.Errorf("duplicate approved DNS name")
		}
		p.allowed[name] = struct{}{}
		p.names = append(p.names, name)
	}
	if len(p.names) > 0 && resolver == nil {
		return nil, fmt.Errorf("approved names require an explicit upstream resolver")
	}
	slices.Sort(p.names)
	for i, prefixes := range [][]netip.Prefix{cfg.ClientNets, cfg.AnswerNets} {
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
				return nil, fmt.Errorf("DNS CIDRs must be canonical IPv4 or IPv6 networks")
			}
			if i == 0 {
				p.clients = append(p.clients, prefix)
			} else {
				p.answers = append(p.answers, prefix)
			}
		}
	}
	return p, nil
}

func canonicalName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) > 253 || !strings.Contains(name, ".") {
		return "", fmt.Errorf("approved DNS names must be exact ASCII hostnames")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("DNS names cannot be IP literals")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("only literal ASCII LDH DNS names are allowed; no wildcards")
			}
		}
	}
	return name + ".", nil
}

func (p *Proxy) Stats() Stats {
	return Stats{p.queries.Load(), p.denied.Load(), p.upstream.Load(), p.failures.Load()}
}

// Refresh is called by the operator lifecycle, never by the request path.
// Replacement is atomic; a failed refresh removes the old answer. Expiration
// also fails closed if the refresh loop stops or hangs.
func (p *Proxy) Refresh(ctx context.Context) {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	next := make(map[string]entry, len(p.names))
	for i := 0; i < min(8, len(p.names)); i++ {
		wg.Go(func() {
			for name := range jobs {
				started := time.Now()
				lookupCtx, cancel := context.WithTimeout(ctx, p.timeout)
				p.upstream.Add(1)
				resolved, err := p.resolver.Resolve(lookupCtx, name)
				ips := resolved.Addresses
				cancel()
				remaining := resolved.TTL - time.Since(started)
				e := entry{code: dnsmessage.RCodeServerFailure, expires: time.Now().Add(2 * p.interval)}
				if err == nil && remaining > 0 && len(ips) > 0 && len(ips) <= MaxAnswers {
					valid := true
					for _, ip := range ips {
						valid = valid && p.answerAllowed(ip)
					}
					if valid {
						e.addresses = slices.Clone(ips)
						slices.SortFunc(e.addresses, func(a, b netip.Addr) int { return a.Compare(b) })
						e.addresses = slices.Compact(e.addresses)
						e.code = dnsmessage.RCodeSuccess
						e.expires = time.Now().Add(min(remaining, 2*p.interval))
					}
				}
				if e.code != dnsmessage.RCodeSuccess {
					p.failures.Add(1)
				}
				mu.Lock()
				next[name] = e
				mu.Unlock()
			}
		})
	}
	for _, name := range p.names {
		select {
		case jobs <- name:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	p.mu.Lock()
	p.cache = next
	p.mu.Unlock()
}

func (p *Proxy) RunRefresh(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	p.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Refresh(ctx)
		}
	}
}

func (p *Proxy) answerAllowed(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return false
	}
	if len(p.answers) == 0 {
		return egress.IsPublicAddress(ip)
	}
	for _, prefix := range p.answers {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *Proxy) clientAllowed(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range p.clients {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// One bounded global bucket avoids attacker-controlled per-source allocations.
func (p *Proxy) takeToken() bool {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	now := time.Now()
	p.tokens = min(100, p.tokens+now.Sub(p.lastToken).Seconds()*50)
	p.lastToken = now
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}
