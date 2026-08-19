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

package utility

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "downloaded content")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "nested", "dir", "file.txt")

	ctx := context.Background()
	client := ts.Client()

	if err := DownloadFile(ctx, client, ts.URL+"/file.txt", destPath, false); err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}
	if string(data) != "downloaded content" {
		t.Errorf("content = %q, want %q", string(data), "downloaded content")
	}

	// Test skipExisting = true
	if err := DownloadFile(ctx, client, ts.URL+"/404-should-skip", destPath, true); err != nil {
		t.Fatalf("DownloadFile with skipExisting should have succeeded without error, got %v", err)
	}

	// Test 404
	err = DownloadFile(ctx, client, ts.URL+"/nonexistent", filepath.Join(tempDir, "404.txt"), false)
	if err == nil {
		t.Errorf("Expected error for 404, got nil")
	}
}
