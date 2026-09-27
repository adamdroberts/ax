// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// ax-dns-proxy serves a default-deny, periodically refreshed DNS namespace.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/ax/pkg/security/dnsproxy"
)

type values []string

func (v *values) String() string         { return strings.Join(*v, ",") }
func (v *values) Set(value string) error { *v = append(*v, value); return nil }

func prefixes(values []string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid configured CIDR")
		}
		result = append(result, prefix)
	}
	return result, nil
}

func run() error {
	var names, clients, answers values
	flag.Var(&names, "allow-name", "Exact approved DNS hostname; repeatable, no wildcards, default denies all")
	flag.Var(&clients, "client-net", "Approved client CIDR; repeatable, default denies all clients")
	flag.Var(&answers, "answer-net", "Approved answer CIDR; repeatable, default public addresses only")
	listen := flag.String("listen", "127.0.0.1:5353", "UDP and TCP listen IP:port")
	upstream := flag.String("upstream", "", "Pinned trusted resolver IP:port; required with --allow-name")
	refresh := flag.Duration("refresh", time.Minute, "Independent name refresh interval (10s..5m)")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument")
	}
	clientNets, err := prefixes(clients)
	if err != nil {
		return err
	}
	answerNets, err := prefixes(answers)
	if err != nil {
		return err
	}
	var resolver dnsproxy.Resolver
	if *upstream != "" {
		resolver, err = dnsproxy.PinnedResolver(*upstream)
		if err != nil {
			return err
		}
	}
	p, err := dnsproxy.New(dnsproxy.Config{AllowedNames: names, ClientNets: clientNets, AnswerNets: answerNets, RefreshInterval: *refresh}, resolver)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var workers sync.WaitGroup
	workers.Go(func() { p.RunRefresh(ctx) })
	workers.Go(func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				s := p.Stats()
				slog.Info("DNS proxy counters", "queries", s.Queries, "denied", s.Denied, "upstream_lookups", s.UpstreamLookups, "refresh_failures", s.RefreshFailures)
			}
		}
	})
	slog.Info("starting DNS proxy", "listen", *listen, "approved_names", len(names), "client_networks", len(clients))
	err = p.ListenAndServe(ctx, *listen)
	stop()
	workers.Wait()
	return err
}

func main() {
	if err := run(); err != nil {
		slog.Error("DNS proxy stopped", "error", err)
		os.Exit(1)
	}
}
