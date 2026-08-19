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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

var testXZPayload = []byte{
	0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
	0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
	0x01, 0x00, 0x1d, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x44, 0x65, 0x62,
	0x69, 0x61, 0x6e, 0x20, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68,
	0x74, 0x20, 0x4d, 0x69, 0x72, 0x72, 0x6f, 0x72, 0x21, 0x00, 0x00, 0x00,
	0xc7, 0x2f, 0x01, 0x8a, 0x65, 0x5a, 0x9a, 0x97, 0x00, 0x01, 0x36, 0x1e,
	0x3d, 0x19, 0x95, 0x53, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x59, 0x5a,
}

func TestDecompressXZ(t *testing.T) {
	ctx := context.Background()
	reader, err := DecompressXZ(ctx, bytes.NewReader(testXZPayload))
	if err != nil {
		t.Fatalf("DecompressXZ failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	want := "Hello Debian Copyright Mirror!"
	if string(data) != want {
		t.Errorf("Decompressed = %q, want %q", string(data), want)
	}
}

func TestDecompressXZFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.xz")
	if err := os.WriteFile(filePath, testXZPayload, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.Background()
	reader, err := DecompressXZFile(ctx, filePath)
	if err != nil {
		t.Fatalf("DecompressXZFile failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	want := "Hello Debian Copyright Mirror!"
	if string(data) != want {
		t.Errorf("Decompressed = %q, want %q", string(data), want)
	}
}

func TestFetchAndDecompressXZ(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(testXZPayload)
	}))
	defer ts.Close()

	ctx := context.Background()
	client := ts.Client()

	reader, err := FetchAndDecompressXZ(ctx, client, ts.URL+"/file.xz")
	if err != nil {
		t.Fatalf("FetchAndDecompressXZ failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	want := "Hello Debian Copyright Mirror!"
	if string(data) != want {
		t.Errorf("Decompressed = %q, want %q", string(data), want)
	}
}
