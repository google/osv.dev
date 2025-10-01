package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const testdataPath = "../../test_data/combine-to-osv"

func TestLoadOSV(t *testing.T) {
	cve5Path := filepath.Join(testdataPath, "cve5")
	allVulns := loadOSV(cve5Path)

	if len(allVulns) != 4 {
		t.Errorf("Expected 4 vulnerabilities, got %d", len(allVulns))
	}

	if _, ok := allVulns["CVE-2023-1234"]; !ok {
		t.Error("Expected to load CVE-2023-1234")
	}
}

func TestCombineIntoOSV(t *testing.T) {
	cve5Path := filepath.Join(testdataPath, "cve5")
	nvdPath := filepath.Join(testdataPath, "nvd")

	cve5osv := loadOSV(cve5Path)
	nvdosv := loadOSV(nvdPath)
	nvdosvCopy := make(map[cves.CVEID]osvschema.Vulnerability)
	for k, v := range nvdosv {
		nvdosvCopy[k] = v
	}
	noPkgCVEs := []string{"CVE-2023-0003"}

	combined := combineIntoOSV(cve5osv, nvdosvCopy, noPkgCVEs)

	// Expected results
	// CVE-2023-1234: merged
	// CVE-2023-0001: from cve5 only
	// CVE-2023-0002: from nvd only
	// CVE-2023-0003: from cve5, no affected, but in noPkgCVEs
	// CVE-2023-0004: from cve5, no affected, not in noPkgCVEs, so skipped
	if len(combined) != 4 {
		t.Errorf("Expected 4 combined vulnerabilities, got %d", len(combined))
	}

	// Test case 1: Merged CVE
	cve1234, ok := combined["CVE-2023-1234"]
	if !ok {
		t.Fatal("Expected combined map to contain CVE-2023-1234")
	}

	// Check modified and published dates
	expectedModified, _ := time.Parse(time.RFC3339, "2023-01-02T12:00:00Z")
	if !cve1234.Modified.Equal(expectedModified) {
		t.Errorf("CVE-2023-1234: expected modified time %v, got %v", expectedModified, cve1234.Modified)
	}
	expectedPublished, _ := time.Parse(time.RFC3339, "2023-01-01T09:00:00Z")
	if !cve1234.Published.Equal(expectedPublished) {
		t.Errorf("CVE-2023-1234: expected published time %v, got %v", expectedPublished, cve1234.Published)
	}

	// Check references
	if len(cve1234.References) != 2 {
		t.Errorf("CVE-2023-1234: expected 2 references, got %d", len(cve1234.References))
	}

	// Check aliases
	if len(cve1234.Aliases) != 2 {
		t.Errorf("CVE-2023-1234: expected 2 aliases, got %d", len(cve1234.Aliases))
	}

	// Check affected (based on pickAffectedInformation logic)
	var affectedForRepoA osvschema.Affected
	foundAffected := false
	for _, a := range cve1234.Affected {
		if len(a.Ranges) > 0 && a.Ranges[0].Repo == "https://example.com/repo/a" {
			affectedForRepoA = a
			foundAffected = true
			break
		}
	}
	if !foundAffected {
		t.Fatal("Did not find affected for repo https://example.com/repo/a")
	}

	expectedRange := osvschema.Range{
		Type: "GIT",
		Repo: "https://example.com/repo/a",
		Events: []osvschema.Event{
			{Introduced: "1.0.0"},
			{Fixed: "1.0.1"},
		},
	}

	// The current logic for pickAffectedInformation when len(cveRanges) == 1 && len(nvdRanges) == 1
	// is to prefer cve5 data.
	if diff := cmp.Diff(expectedRange, affectedForRepoA.Ranges[0]); diff != "" {
		t.Errorf("CVE-2023-1234: affected range mismatch (-want +got):\n%s", diff)
	}

	// Test case 2: CVE only in cve5
	if _, ok = combined["CVE-2023-0001"]; !ok {
		t.Error("Expected combined map to contain CVE-2023-0001")
	}

	// Test case 3: CVE only in nvd
	if _, ok = combined["CVE-2023-0002"]; !ok {
		t.Error("Expected combined map to contain CVE-2023-0002")
	}

	// Test case 4: No affected, in noPkgCVEs
	if _, ok = combined["CVE-2023-0003"]; !ok {
		t.Error("Expected combined map to contain CVE-2023-0003")
	}

	// Test case 5: No affected, not in noPkgCVEs
	if _, ok = combined["CVE-2023-0004"]; ok {
		t.Error("Expected combined map to NOT contain CVE-2023-0004")
	}
}

func TestPickAffectedInformation(t *testing.T) {
	repoA := "https://example.com/repo/a"
	cve5Affected := []osvschema.Affected{
		{
			Ranges: []osvschema.Range{
				{
					Type: "GIT",
					Repo: repoA,
					Events: []osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
		},
	}
	nvdAffected := []osvschema.Affected{
		{
			Ranges: []osvschema.Range{
				{
					Type: "GIT",
					Repo: repoA,
					Events: []osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.2"},
					},
				},
			},
		},
	}

	// Test case: NVD has more affected packages
	cve5WithOne := cve5Affected
	nvdWithTwo := append(nvdAffected, osvschema.Affected{Package: osvschema.Package{Name: "another"}})
	pickAffectedInformation(&cve5WithOne, nvdWithTwo)
	if len(cve5WithOne) != 2 {
		t.Errorf("Expected NVD affected to be chosen when it has more packages")
	}

	// Test case: Same repo, same number of ranges, cve5 data is preferred
	cve5Copy := make([]osvschema.Affected, len(cve5Affected))
	copy(cve5Copy, cve5Affected)
	pickAffectedInformation(&cve5Copy, nvdAffected)
	if cve5Copy[0].Ranges[0].Events[1].Fixed != "1.0.1" {
		t.Errorf("Expected cve5 fixed version to be preferred, got %s", cve5Copy[0].Ranges[0].Events[1].Fixed)
	}
}
