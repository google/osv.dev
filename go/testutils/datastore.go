// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law of agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package testutils provides utilities for testing.
package testutils

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
)

const (
	datastoreEmulatorHost      = "localhost"
	datastoreEmulatorProjectID = "test-project"
	startupTimeout             = 30 * time.Second
	httpTimeout                = 10 * time.Second
)

var (
	emulatorPort       string
	emulatorHTTPClient = &http.Client{Timeout: httpTimeout}
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func getFreePort() (string, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return "", err
	}
	defer listener.Close()

	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}

func resetEmulator(t *testing.T) {
	t.Helper()
	resetURL := fmt.Sprintf("http://%s/reset", net.JoinHostPort(datastoreEmulatorHost, emulatorPort))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, resetURL, nil)
	if err != nil {
		t.Fatalf("Failed to create reset request: %v", err)
	}
	resp, err := emulatorHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send reset request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to reset emulator, status: %s", resp.Status)
	}
}

func startDatastoreEmulator() (*exec.Cmd, error) {
	port, err := getFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to get free port: %w", err)
	}
	emulatorPort = port
	hostPort := net.JoinHostPort(datastoreEmulatorHost, emulatorPort)

	//nolint:gosec
	cmd := exec.Command("gcloud", "emulators", "firestore", "start",
		"--database-mode=datastore-mode",
		"--host-port="+hostPort)
	// Start the emulator in its own process group so we can kill gcloud,
	// its bash wrapper, and the underlying Java process together.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var output syncBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start datastore emulator: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	healthURL := "http://" + hostPort + "/"
	ready := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			reqCtx, reqCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, healthURL, nil)
			if err == nil {
				resp, err := emulatorHTTPClient.Do(req)
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						reqCancel()
						close(ready)

						return
					}
				}
			}
			reqCancel()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-ctx.Done():
		stopDatastoreEmulator(cmd)

		return nil, fmt.Errorf("datastore emulator did not start in time: %w\nOutput:\n%s", ctx.Err(), output.String())
	case <-ready:
	}

	os.Setenv("DATASTORE_EMULATOR_HOST", hostPort)
	os.Setenv("DATASTORE_PROJECT_ID", datastoreEmulatorProjectID)

	return cmd, nil
}

func stopDatastoreEmulator(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}
}

// RunWithDatastoreEmulator starts the Datastore emulator for a test package,
// runs m.Run(), stops the emulator process group, and exits with the test status code.
func RunWithDatastoreEmulator(m *testing.M) {
	cmd, err := startDatastoreEmulator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Datastore emulator setup failed: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	stopDatastoreEmulator(cmd)
	os.Exit(code)
}

// MustNewDatastoreClientForTesting creates a new Datastore client connected to the emulator
// and resets the emulator state for the test.
// The package's TestMain must call RunWithDatastoreEmulator.
func MustNewDatastoreClientForTesting(t *testing.T) *datastore.Client {
	t.Helper()
	if emulatorPort == "" {
		t.Fatal("Datastore emulator is not running; call testutils.RunWithDatastoreEmulator(m) in TestMain")
	}
	resetEmulator(t)

	client, err := datastore.NewClient(context.Background(), datastoreEmulatorProjectID)
	if err != nil {
		t.Fatalf("Failed to create Datastore client: %v", err)
	}

	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("Failed to close Datastore client: %v", err)
		}
	})

	return client
}
