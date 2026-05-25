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

	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestLoadExisting(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Write a valid vulnerability YAML
	validYaml := `
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
id: PYSEC-2021-456
aliases:
  - CVE-2021-67890
`
	if err := os.WriteFile(filepath.Join(tmpDir, "missing_affected.yaml"), []byte(missingAffectedYaml), 0600); err != nil {
		t.Fatalf("failed to write YAML with missing affected: %v", err)
	}

	// 3. Write a vulnerability YAML with affected block but missing package
	missingPackageYaml := `
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

func strPtr(s string) *string {
	return &s
}

func TestGeneratePyPIAffected(t *testing.T) {
	cve := models.NVDCVE{
		ID:      "CVE-2022-29194",
		Metrics: &models.CVEItemMetrics{},
		Configurations: []models.Config{
			{
				Nodes: []models.Node{
					{
						Operator: "OR",
						CPEMatch: []models.CPEMatch{
							{
								Vulnerable:          true,
								Criteria:            "cpe:2.3:a:google:tensorflow:*:*:*:*:*:*:*:*",
								VersionEndExcluding: strPtr("2.6.4"),
							},
							{
								Vulnerable:            true,
								Criteria:              "cpe:2.3:a:google:tensorflow:*:*:*:*:*:*:*:*",
								VersionStartIncluding: strPtr("2.7.0"),
								VersionEndExcluding:   strPtr("2.7.2"),
							},
						},
					},
				},
			},
		},
	}

	validVersions := []string{
		"2.5.0", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4",
		"2.7.0", "2.7.1", "2.7.2",
	}
	pkg := "tensorflow"
	purl := "pkg:pypi/tensorflow"
	metrics := &models.ConversionMetrics{
		CVEID: cve.ID,
	}

	v := generatePyPIAffected(cve, pkg, validVersions, purl, metrics)

	// Verify ID
	expectedID := "PYSEC-0000-CVE-2022-29194"
	if v.Id != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, v.Id)
	}

	// Verify Affected
	if len(v.Affected) != 1 {
		t.Fatalf("expected exactly 1 affected entry, got %d", len(v.Affected))
	}

	affected := v.Affected[0]

	// Verify Package
	if affected.GetPackage() == nil {
		t.Fatal("expected non-nil affected.Package")
	}
	if affected.GetPackage().GetName() != pkg {
		t.Errorf("expected package name %q, got %q", pkg, affected.GetPackage().GetName())
	}
	if affected.GetPackage().GetEcosystem() != "PyPI" {
		t.Errorf("expected package ecosystem %q, got %q", "PyPI", affected.GetPackage().GetEcosystem())
	}
	if affected.GetPackage().GetPurl() != purl {
		t.Errorf("expected package PURL %q, got %q", purl, affected.GetPackage().GetPurl())
	}

	// Verify Ranges
	if len(affected.GetRanges()) != 1 {
		t.Fatalf("expected exactly 1 range entry, got %d", len(affected.GetRanges()))
	}

	r := affected.GetRanges()[0]
	if r.GetType() != osvschema.Range_ECOSYSTEM {
		t.Errorf("expected range type %v, got %v", osvschema.Range_ECOSYSTEM, r.GetType())
	}

	// Log all generated events for debugging
	for i, ev := range r.GetEvents() {
		t.Logf("Generated Event[%d]: %+v", i, ev)
	}

	// Verify Events
	expectedEvents := []*osvschema.Event{
		{Introduced: "0"},
		{Fixed: "2.6.4"},
		{Introduced: "2.7.0"},
		{Fixed: "2.7.2"},
	}

	if len(r.GetEvents()) != len(expectedEvents) {
		t.Fatalf("expected %d events, got %d", len(expectedEvents), len(r.GetEvents()))
	}

	for i, ev := range r.GetEvents() {
		expectedEv := expectedEvents[i]
		if ev.GetIntroduced() != expectedEv.GetIntroduced() {
			t.Errorf("event[%d]: expected introduced %q, got %q", i, expectedEv.GetIntroduced(), ev.GetIntroduced())
		}
		if ev.GetFixed() != expectedEv.GetFixed() {
			t.Errorf("event[%d]: expected fixed %q, got %q", i, expectedEv.GetFixed(), ev.GetFixed())
		}
	}
}
