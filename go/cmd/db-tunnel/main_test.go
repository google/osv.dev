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

package main

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

func TestParseMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    string
		want    []mapping
		wantErr bool
	}{
		{
			name: "single loopback mapping",
			spec: "127.0.0.1:5432=10.25.1.3:5432",
			want: []mapping{
				{listenAddr: "127.0.0.1:5432", targetAddr: "10.25.1.3:5432"},
			},
		},
		{
			name: "multiple mappings with whitespace",
			spec: " 127.0.0.1:5432=10.25.1.3:5432 , 127.0.0.1:6432=10.25.1.7:6432 , ",
			want: []mapping{
				{listenAddr: "127.0.0.1:5432", targetAddr: "10.25.1.3:5432"},
				{listenAddr: "127.0.0.1:6432", targetAddr: "10.25.1.7:6432"},
			},
		},
		{
			name:    "empty",
			spec:    "  ",
			wantErr: true,
		},
		{
			name:    "only commas",
			spec:    " , , ",
			wantErr: true,
		},
		{
			name:    "missing equals",
			spec:    "127.0.0.1:5432",
			wantErr: true,
		},
		{
			name:    "invalid listen addr",
			spec:    "not-a-hostport=10.25.1.3:5432",
			wantErr: true,
		},
		{
			name:    "empty listen port",
			spec:    "127.0.0.1:=10.25.1.3:5432",
			wantErr: true,
		},
		{
			name:    "empty target host",
			spec:    "127.0.0.1:5432=:5432",
			wantErr: true,
		},
		{
			name:    "empty target port",
			spec:    "127.0.0.1:5432=10.25.1.3:",
			wantErr: true,
		},
		{
			name:    "invalid target addr",
			spec:    "127.0.0.1:5432=10.25.1.3",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseMappings(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMappings(%q) succeeded (%+v), want error", tc.spec, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseMappings(%q) unexpected error: %v", tc.spec, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseMappings(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestRunListenerForwardsTraffic(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	var lc net.ListenConfig

	// Start a mock upstream TCP echo server.
	backendLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = backendLn.Close() })

	go func() {
		conn, acceptErr := backendLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	// Start tunnel listener pointing at the mock backend.
	tunnelLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen tunnel: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runListener(ctx, tunnelLn, backendLn.Addr().String())
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	var dialer net.Dialer
	client, err := dialer.DialContext(ctx, "tcp", tunnelLn.Addr().String())
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer client.Close()

	const payload = "hello private cloud sql"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed payload = %q, want %q", string(got), payload)
	}
}

func TestRunListenerClosesActiveConnOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	var lc net.ListenConfig

	// Backend accepts a connection and holds it open until closed.
	backendLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = backendLn.Close() })

	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := backendLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn)
	}()

	tunnelLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen tunnel: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runListener(ctx, tunnelLn, backendLn.Addr().String())
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	var dialer net.Dialer
	client, err := dialer.DialContext(ctx, "tcp", tunnelLn.Addr().String())
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer client.Close()

	<-accepted

	// Cancelling context must close the active proxied connection and return promptly.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runListener did not exit promptly after context cancel with active connection")
	}
}

func TestProxyConnUnreachableUpstream(t *testing.T) {
	t.Parallel()

	// Allocate and immediately close a local port so dialing it fails fast.
	var lc net.ListenConfig
	closedLn, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen temp: %v", err)
	}
	deadAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	c1, c2 := net.Pipe()
	defer c2.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyConn(t.Context(), c1, deadAddr)
	}()

	// Client side should observe EOF/close once proxyConn fails to dial upstream.
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("Read() succeeded, want error after upstream dial failure")
	}
	<-done
}

func TestRunPartialBindFailureCleansUpListeners(t *testing.T) {
	t.Parallel()

	var lc net.ListenConfig
	// Reserve an address to cause the first mapping to succeed and a duplicate
	// listen address to fail, then confirm the first address was closed cleanly.
	probe, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	freeAddr := probe.Addr().String()
	_ = probe.Close()

	err = run(t.Context(), []mapping{
		{listenAddr: freeAddr, targetAddr: "127.0.0.1:5432"},
		{listenAddr: freeAddr, targetAddr: "127.0.0.1:6432"},
	})
	if err == nil {
		t.Fatal("run() succeeded on conflicting listen addresses, want error")
	}

	// If run() properly closed the first listener, re-binding freeAddr succeeds.
	rebound, err := lc.Listen(t.Context(), "tcp", freeAddr)
	if err != nil {
		t.Fatalf("re-binding %s after partial bind failure failed (listener leaked): %v", freeAddr, err)
	}
	_ = rebound.Close()
}
