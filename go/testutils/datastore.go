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
	"testing"
	"time"

	"cloud.google.com/go/datastore"
)

const (
	datastoreEmulatorHost      = "localhost"
	datastoreEmulatorProjectID = "test-project"
	startupTimeout             = 30 * time.Second
)

var (
	emulatorCmd  *exec.Cmd
	emulatorPort string
	emulatorOnce sync.Once
	emulatorErr  error //nolint:errname // This is error state of the emulator, not an error type
)

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
	req, err := http.NewRequest(http.MethodPost, resetURL, nil)
	if err != nil {
		t.Fatalf("Failed to create reset request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send reset request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to reset emulator, status: %s", resp.Status)
	}
}

// StartDatastoreEmulator ensures the Datastore emulator is running once per test execution.
func StartDatastoreEmulator(t *testing.T) {
	t.Helper()
	emulatorOnce.Do(func() {
		port, err := getFreePort()
		if err != nil {
			emulatorErr = fmt.Errorf("failed to get free port: %w", err)
			return
		}
		emulatorPort = port

		//nolint:gosec
		emulatorCmd = exec.Command("gcloud", "emulators", "firestore", "start",
			"--database-mode=datastore-mode",
			fmt.Sprintf("--host-port=%s:%s", datastoreEmulatorHost, emulatorPort))

		var output bytes.Buffer
		emulatorCmd.Stdout = &output
		emulatorCmd.Stderr = &output

		if err := emulatorCmd.Start(); err != nil {
			emulatorErr = fmt.Errorf("failed to start datastore emulator: %w", err)
			return
		}

		// Wait for the emulator to be ready
		ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
		defer cancel()

		ready := make(chan struct{})
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(datastoreEmulatorHost, emulatorPort), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					close(ready)

					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		select {
		case <-ctx.Done():
			emulatorErr = fmt.Errorf("datastore emulator did not start in time: %w\nOutput:\n%s", ctx.Err(), output.String())
			return
		case <-ready:
			t.Log("Datastore emulator is ready")
		}

		t.Cleanup(func() {
			t.Log("Stopping Datastore emulator")
			if emulatorCmd != nil && emulatorCmd.Process != nil {
				if err := emulatorCmd.Process.Kill(); err != nil {
					t.Logf("Failed to kill datastore emulator: %v", err)
				}
				_ = emulatorCmd.Wait()
			}
			os.Unsetenv("DATASTORE_EMULATOR_HOST")
			os.Unsetenv("DATASTORE_PROJECT_ID")
		})
	})

	if emulatorErr != nil {
		t.Fatalf("Datastore emulator setup failed: %v", emulatorErr)
	}

	t.Setenv("DATASTORE_EMULATOR_HOST", net.JoinHostPort(datastoreEmulatorHost, emulatorPort))
	t.Setenv("DATASTORE_PROJECT_ID", datastoreEmulatorProjectID)
	resetEmulator(t)
}

// MustNewDatastoreClientForTesting creates a new Datastore client connected to the emulator.
// It ensures the emulator is started and cleaned up.
func MustNewDatastoreClientForTesting(t *testing.T) *datastore.Client {
	t.Helper()
	StartDatastoreEmulator(t)

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
