// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main runs the AX Model Context Protocol (MCP) security proxy server.
//
// It operates over stdio, providing agents with safe HTTP/API proxy tools
// ('http_request') that inspect every request payload against Snort intrusion
// and exploit prevention rules before network transmission.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/ax/pkg/mcp/proxy"
	"github.com/google/ax/pkg/security/snort"
)

type originFlags []string

func (o *originFlags) String() string         { return strings.Join(*o, ",") }
func (o *originFlags) Set(value string) error { *o = append(*o, value); return nil }

func main() {
	var origins originFlags
	flag.Var(&origins, "allow-origin", "Allow one exact HTTP(S) origin (repeatable; default denies all network egress)")
	profile := flag.String("profile", "default", "Built-in policy profile: default or strict")
	rulesPath := flag.String("rules", "", "Path to custom Snort .rules file")
	onlyCustom := flag.Bool("only-custom-rules", false, "Load only custom rules without default rules")
	verbose := flag.Bool("verbose", false, "Enable verbose logging to stderr")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var engine *snort.Engine
	var err error

	if *profile != "default" && *profile != "strict" {
		slog.Error("unknown policy profile", "profile", *profile)
		os.Exit(1)
	}
	if *onlyCustom && *rulesPath == "" {
		slog.Error("--only-custom-rules requires a non-empty --rules file")
		os.Exit(1)
	}
	if *onlyCustom {
		engine = snort.NewEngine()
	} else {
		engine, err = snort.NewProfileEngine(*profile)
		if err != nil {
			slog.Error("failed to load built-in snort rules", "error", err)
			os.Exit(1)
		}
		slog.Info("loaded built-in snort rules", "profile", *profile, "count", engine.RuleCount())
	}

	if *rulesPath != "" {
		count, err := engine.LoadRulesFromFile(*rulesPath)
		if err != nil {
			slog.Error("failed to load custom snort rules", "path", *rulesPath, "error", err)
			os.Exit(1)
		}
		slog.Info("loaded custom snort rules", "path", *rulesPath, "added_count", count, "total_rules", engine.RuleCount())
	}

	if engine.RuleCount() == 0 {
		slog.Error("refusing to start with no active security rules")
		os.Exit(1)
	}

	server, err := proxy.NewServer(proxy.WithEngine(engine), proxy.WithAllowedOrigins(origins...))
	if err != nil {
		slog.Error("failed to create MCP proxy server", "error", err)
		os.Exit(1)
	}

	slog.Info("starting ax-mcp-proxy server on stdio", "active_rules", engine.RuleCount())
	if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		if ctx.Err() == nil {
			slog.Error("server terminated with error", "error", err)
			os.Exit(1)
		}
	}
	slog.Info("ax-mcp-proxy server stopped cleanly")
	fmt.Fprintf(os.Stderr, "ax-mcp-proxy stopped\n")
}
