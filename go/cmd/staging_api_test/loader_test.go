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
	"archive/zip"
	"bytes"
	"context"
	"math/rand/v2"
	"testing"
)

func TestFormatVuln(t *testing.T) {
	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(42, 42))

	t.Run("NoAffected", func(t *testing.T) {
		raw := rawVulnerability{ID: "TEST-001"}
		vuln := formatVuln(rng, raw)
		if vuln.ID != "TEST-001" {
			t.Errorf("expected ID TEST-001, got %s", vuln.ID)
		}
		if vuln.Package != "foo" || vuln.Ecosystem != "foo" || vuln.PURL != "pkg:foo/foo" || vuln.AffectedFuzzy != "1.0.0" {
			t.Errorf("unexpected defaults for vuln: %+v", vuln)
		}
	})

	t.Run("WithVersions", func(t *testing.T) {
		raw := rawVulnerability{
			ID: "TEST-002",
			Affected: []rawAffected{
				{
					Package: &rawPackage{
						Name:      "mypackage",
						Ecosystem: "PyPI",
						PURL:      "pkg:pypi/mypackage",
					},
					Versions: []string{"1.2.3"},
				},
			},
		}
		vuln := formatVuln(rng, raw)
		if vuln.ID != "TEST-002" {
			t.Errorf("expected ID TEST-002, got %s", vuln.ID)
		}
		if vuln.Package != "mypackage" || vuln.Ecosystem != "PyPI" || vuln.PURL != "pkg:pypi/mypackage" {
			t.Errorf("unexpected package details: %+v", vuln)
		}
		if vuln.AffectedFuzzy != "1.2.3" {
			t.Errorf("expected AffectedFuzzy 1.2.3, got %s", vuln.AffectedFuzzy)
		}
	})

	t.Run("WithRangesEvents", func(t *testing.T) {
		raw := rawVulnerability{
			ID: "TEST-003",
			Affected: []rawAffected{
				{
					Package: &rawPackage{
						Name:      "curl",
						Ecosystem: "Debian",
					},
					Ranges: []rawRange{
						{
							Type: "ECOSYSTEM",
							Events: []map[string]string{
								{"introduced": "0", "fixed": "7.88.1"},
							},
						},
					},
				},
			},
		}
		vuln := formatVuln(rng, raw)
		if vuln.ID != "TEST-003" {
			t.Errorf("expected ID TEST-003, got %s", vuln.ID)
		}
		if vuln.Package != "curl" || vuln.Ecosystem != "Debian" {
			t.Errorf("unexpected package details: %+v", vuln)
		}
		if vuln.AffectedFuzzy != "0" && vuln.AffectedFuzzy != "7.88.1" {
			t.Errorf("expected fuzzy version from event, got %s", vuln.AffectedFuzzy)
		}
	})
}

func createTestZip(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip file entry: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip file entry content: %v", err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to create zip reader: %v", err)
	}

	return reader
}

func TestLoadQueryPoolsFromZip(t *testing.T) {
	files := map[string]string{
		"vuln1.json": `{
			"id": "OSV-2024-001",
			"affected": [{
				"package": {"name": "pkg-a", "ecosystem": "npm", "purl": "pkg:npm/pkg-a"},
				"versions": ["1.0.0", "1.0.1"]
			}]
		}`,
		"vuln2.json": `{
			"id": "OSV-2024-002",
			"affected": [{
				"package": {"name": "pkg-a", "ecosystem": "npm"},
				"versions": ["2.0.0"]
			}]
		}`,
		"vuln3.json": `{
			"id": "OSV-2024-003",
			"affected": [{
				"package": {"name": "pkg-b", "ecosystem": "PyPI"},
				"versions": ["0.1.0"]
			}]
		}`,
		"vuln4.json": `{
			"id": "OSV-2024-004",
			"affected": [{
				"package": {"name": "Kernel", "ecosystem": "Linux"},
				"versions": ["5.10.0"]
			}]
		}`,
		"invalid.json": `not valid json`,
		"readme.txt":   `hello world`,
	}

	zipReader := createTestZip(t, files)
	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(123, 123))

	pools, err := LoadQueryPoolsFromZip(context.Background(), zipReader, rng)
	if err != nil {
		t.Fatalf("unexpected error loading pools: %v", err)
	}

	if len(pools.VulnMap) != 4 {
		t.Errorf("expected 4 vulns in VulnMap, got %d", len(pools.VulnMap))
	}
	if len(pools.VulnQueryIDs) != 4 {
		t.Errorf("expected 4 vulnQueryIDs, got %d", len(pools.VulnQueryIDs))
	}

	// Package query IDs should have 1 entry per distinct package
	expectedPackages := map[string]bool{"pkg-a": true, "pkg-b": true, "Kernel": true}
	if len(pools.PackageQueryIDs) != len(expectedPackages) {
		t.Errorf("expected %d packageQueryIDs, got %d", len(expectedPackages), len(pools.PackageQueryIDs))
	}

	// Large batch queries should exclude "Kernel" and "foo"
	for _, id := range pools.LargeBatchQueryIDs {
		vuln := pools.VulnMap[id]
		if vuln.Package == "Kernel" || vuln.Package == "foo" {
			t.Errorf("expected Kernel/foo to be excluded from LargeBatchQueryIDs, found %+v", vuln)
		}
	}
}
