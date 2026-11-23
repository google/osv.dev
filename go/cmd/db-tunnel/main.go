// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command db-tunnel is a lightweight raw-TCP forwarder deployed inside GKE so
// authorized engineers can reach Private-IP-only Cloud SQL instances from
// workstations via `kubectl port-forward` without exposing a database public IP.
// This binary holds no credentials and only relays TCP bytes; clients should
// authenticate with TLS + personal GCP IAM login tokens (and use
// sslmode=verify-ca with the Cloud SQL server CA cert to protect against
// in-cluster MITM).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout      = 10 * time.Second
	maxConns         = 128
	initialBackoff   = 5 * time.Millisecond
	maxAcceptBackoff = 1 * time.Second
)

type mapping struct {
	listenAddr string
	targetAddr string
}

func parseMappings(spec string) ([]mapping, error) {
	var result []mapping
	for entry := range strings.SplitSeq(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		listenAddr, targetAddr, ok := strings.Cut(entry, "=")
		listenAddr = strings.TrimSpace(listenAddr)
		targetAddr = strings.TrimSpace(targetAddr)
		if !ok {
			return nil, fmt.Errorf("invalid mapping %q: expected listen=target", entry)
		}
		_, listenPort, err := net.SplitHostPort(listenAddr)
		if err != nil || listenPort == "" {
			return nil, fmt.Errorf("invalid listen address %q: must include non-empty port", listenAddr)
		}
		targetHost, targetPort, err := net.SplitHostPort(targetAddr)
		if err != nil || targetHost == "" || targetPort == "" {
			return nil, fmt.Errorf("invalid target address %q: must include non-empty host and port", targetAddr)
		}
		result = append(result, mapping{
			listenAddr: listenAddr,
			targetAddr: targetAddr,
		})
	}
	if len(result) == 0 {
		return nil, errors.New("no tunnel mappings specified (set TUNNEL_MAPPINGS or -mappings)")
	}

	return result, nil
}

func copyHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func proxyConn(ctx context.Context, client net.Conn, targetAddr string) {
	defer client.Close()

	dialer := net.Dialer{Timeout: dialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		slog.Warn("failed to dial upstream", "target", targetAddr, "err", err)

		return
	}
	defer upstream.Close()

	// Close both sockets if shutdown is signaled so blocked io.Copy calls return.
	stopClose := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stopClose()

	var wg sync.WaitGroup
	wg.Go(func() {
		copyHalfClose(upstream, client)
	})
	copyHalfClose(client, upstream)
	wg.Wait()
}

func runListener(ctx context.Context, ln net.Listener, targetAddr string) {
	var wg sync.WaitGroup
	defer wg.Wait()

	stopClose := context.AfterFunc(ctx, func() {
		_ = ln.Close()
	})
	defer stopClose()

	sem := make(chan struct{}, maxConns)
	backoff := initialBackoff

	slog.Info("listening", "listen", ln.Addr().String(), "target", targetAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("accept failed; backing off", "listen", ln.Addr().String(), "backoff", backoff, "err", err)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()

				return
			case <-timer.C:
			}
			backoff = min(backoff*2, maxAcceptBackoff)

			continue
		}
		backoff = initialBackoff

		select {
		case sem <- struct{}{}:
		default:
			slog.Warn("max concurrent connections reached; dropping connection", "listen", ln.Addr().String(), "max_conns", maxConns)
			_ = conn.Close()

			continue
		}

		wg.Go(func() {
			defer func() { <-sem }()
			proxyConn(ctx, conn, targetAddr)
		})
	}
}

func run(ctx context.Context, mappings []mapping) error {
	listeners := make([]net.Listener, 0, len(mappings))
	var lc net.ListenConfig
	for _, m := range mappings {
		ln, err := lc.Listen(ctx, "tcp", m.listenAddr)
		if err != nil {
			for _, existing := range listeners {
				_ = existing.Close()
			}

			return fmt.Errorf("listen %s: %w", m.listenAddr, err)
		}
		listeners = append(listeners, ln)
	}

	var wg sync.WaitGroup
	for i, ln := range listeners {
		target := mappings[i].targetAddr
		wg.Go(func() {
			runListener(ctx, ln, target)
		})
	}
	wg.Wait()

	return nil
}

func main() {
	mappingsFlag := flag.String("mappings", os.Getenv("TUNNEL_MAPPINGS"), "Comma-separated listen=target TCP forwarding pairs (overrides TUNNEL_MAPPINGS)")
	flag.Parse()

	mappings, err := parseMappings(*mappingsFlag)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err = run(ctx, mappings)
	stop()
	if err != nil {
		slog.Error("db-tunnel exited with error", "err", err)
		os.Exit(1)
	}
}
