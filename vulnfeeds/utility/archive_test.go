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
	"os"
	"path/filepath"
	"testing"
)

func TestTarArchiveRoundtrip(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	destDir := filepath.Join(tempDir, "dest")

	if err := os.MkdirAll(filepath.Join(sourceDir, "sub"), 0755); err != nil {
		t.Fatalf("Failed to create test source dir: %v", err)
	}

	file1 := filepath.Join(sourceDir, "file1.txt")
	file2 := filepath.Join(sourceDir, "sub", "file2.txt")
	if err := os.WriteFile(file1, []byte("hello archive"), 0600); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("nested file content"), 0600); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	var buf bytes.Buffer
	if err := CreateTarArchive(sourceDir, &buf); err != nil {
		t.Fatalf("CreateTarArchive failed: %v", err)
	}

	if err := ExtractTarArchive(&buf, destDir); err != nil {
		t.Fatalf("ExtractTarArchive failed: %v", err)
	}

	destFile1 := filepath.Join(destDir, "file1.txt")
	destFile2 := filepath.Join(destDir, "sub", "file2.txt")

	data1, err := os.ReadFile(destFile1)
	if err != nil {
		t.Fatalf("Failed to read extracted file1: %v", err)
	}
	if string(data1) != "hello archive" {
		t.Errorf("file1 content = %q, want %q", string(data1), "hello archive")
	}

	data2, err := os.ReadFile(destFile2)
	if err != nil {
		t.Fatalf("Failed to read extracted file2: %v", err)
	}
	if string(data2) != "nested file content" {
		t.Errorf("file2 content = %q, want %q", string(data2), "nested file content")
	}
}
