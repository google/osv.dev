// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExisting(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Write a valid vulnerability YAML
	validYaml := `
vulnerability:
  id: PYSEC-2021-123
  affected:
    - package:
        name: foo-pkg
        ecosystem: PyPI
  aliases:
    - CVE-2021-12345
`
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validYaml), 0600); err != nil {
		t.Fatalf("failed to write valid YAML: %v", err)
	}

	// 2. Write a vulnerability YAML with empty/missing affected block
	missingAffectedYaml := `
vulnerability:
  id: PYSEC-2021-456
  aliases:
    - CVE-2021-67890
`
	if err := os.WriteFile(filepath.Join(tmpDir, "missing_affected.yaml"), []byte(missingAffectedYaml), 0600); err != nil {
		t.Fatalf("failed to write YAML with missing affected: %v", err)
	}

	// 3. Write a vulnerability YAML with affected block but missing package
	missingPackageYaml := `
vulnerability:
  id: PYSEC-2021-789
  affected:
    - {}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "missing_package.yaml"), []byte(missingPackageYaml), 0600); err != nil {
		t.Fatalf("failed to write YAML with missing package: %v", err)
	}

	// Run loadExisting
	got, err := loadExisting(tmpDir)
	if err != nil {
		t.Fatalf("loadExisting failed: %v", err)
	}

	// Check expected IDs
	expected := map[string]bool{
		"PYSEC-2021-123/foo-pkg": true,
		"CVE-2021-12345/foo-pkg": true,
	}

	if len(got) != len(expected) {
		t.Errorf("loadExisting returned map of size %d, want %d", len(got), len(expected))
	}

	for k, v := range expected {
		if !got[k] {
			t.Errorf("Expected map to contain %s", k)
		}
		if got[k] != v {
			t.Errorf("Expected map[%s] to be %t, got %t", k, v, got[k])
		}
	}

	// Ensure invalid/skipped entries are NOT present
	unexpectedKeys := []string{
		"PYSEC-2021-456/foo-pkg",
		"CVE-2021-67890/foo-pkg",
		"PYSEC-2021-789/foo-pkg",
	}
	for _, k := range unexpectedKeys {
		if got[k] {
			t.Errorf("Map unexpectedly contains %s", k)
		}
	}
}
