package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/internal/testutils"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"golang.org/x/exp/slices"
)

func loadTestData(cveName string) cves.CVE5 {
	prefix := strings.Split(cveName, "-")[2]
	prefixpath := prefix[:len(prefix)-3] + "xxx"
	fileName := filepath.Join("..", "..", "test_data", "cvelistV5", "cves", cveName[4:8], prefixpath, fmt.Sprintf("%s.json", cveName))
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to load test data from %q: %v", fileName, err)
	}
	defer file.Close()
	var cve cves.CVE5
	err = json.NewDecoder(file).Decode(&cve)
	if err != nil {
		log.Fatalf("Failed to decode %q: %+v", fileName, err)
	}
	return cve
}

func TestFromCVE(t *testing.T) {
	cveData := loadTestData("CVE-2021-44228")
	id := cveData.Metadata.CVEID
	refs := identifyPossibleURLs(cveData)
	descriptions := cveData.Containers.CNA.Descriptions
	published, _ := vulns.CVE5timestampToRFC3339(cveData.Metadata.DatePublished)
	modified, _ := vulns.CVE5timestampToRFC3339(cveData.Metadata.DateUpdated)
	metrics := cveData.Containers.CNA.Metrics
	v, notes := vulns.FromCVE(id, id, refs, descriptions, published, modified, metrics)

	if v.ID != "CVE-2021-44228" {
		t.Errorf("Expected ID CVE-2021-44228, got %s", v.ID)
	}

	if !strings.HasPrefix(v.Details, "Apache Log4j2") {
		t.Errorf("Details do not seem correct, got: %s", v.Details)
	}

	expectedPublished := "2021-12-10T00:00:00Z"
	if v.Published != expectedPublished {
		t.Errorf("Published date is incorrect, got: %s, want: %s", v.Published, expectedPublished)
	}

	expectedModified := "2025-02-04T14:25:37Z"
	if v.Modified != expectedModified {
		t.Errorf("Modified date is incorrect, got: %s, want: %s", v.Modified, expectedModified)
	}

	if len(notes) != 0 {
		t.Errorf("Expected no notes, got %v", notes)
	}

	// Check a reference
	foundRef := false
	for _, ref := range v.References {
		if ref.URL == "https://logging.apache.org/log4j/2.x/security.html" {
			foundRef = true
			if ref.Type != "WEB" {
				t.Errorf("Incorrect reference type, got %s, want WEB", ref.Type)
			}
		}
	}
	if !foundRef {
		t.Error("Expected reference not found")
	}
}

func TestExtractVersionInfo(t *testing.T) {
	tests := []struct {
		name                string
		cveID               string
		expectedVersionInfo models.VersionInfo
		expectNotes         bool
	}{
		{
			name:  "CVE with lessThan",
			cveID: "CVE-2025-1110", // GitLab
			expectedVersionInfo: models.VersionInfo{
				AffectedVersions: []models.AffectedVersion{
					{Introduced: "18.0", Fixed: "18.0.1"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := testutils.SetupVCR(t)
			client := r.GetDefaultClient()

			cveData := loadTestData(tc.cveID)
			refs := identifyPossibleURLs(cveData)
			repos := []string{}
			for _, ref := range refs {
				repos = append(repos, ref.Url)
			}
			got, notes := ExtractVersionInfo(cveData, repos, nil, client)

			// Sort for stable comparison
			sort.SliceStable(got.AffectedVersions, func(i, j int) bool {
				return got.AffectedVersions[i].Introduced < got.AffectedVersions[j].Introduced
			})
			sort.SliceStable(tc.expectedVersionInfo.AffectedVersions, func(i, j int) bool {
				return tc.expectedVersionInfo.AffectedVersions[i].Introduced < tc.expectedVersionInfo.AffectedVersions[j].Introduced
			})
			slices.SortStableFunc(got.AffectedCommits, models.AffectedCommitCompare)
			slices.SortStableFunc(tc.expectedVersionInfo.AffectedCommits, models.AffectedCommitCompare)

			if diff := cmp.Diff(tc.expectedVersionInfo, got); diff != "" {
				t.Errorf("ExtractVersionInfo() mismatch (-want +got):\n%s", diff)
			}

			if tc.expectNotes && len(notes) == 0 {
				t.Error("Expected notes, but got none")
			}
			if !tc.expectNotes && len(notes) > 1 && notes[0] != "No versions detected." {
				t.Errorf("Expected no notes, but got: %v", notes)
			}
		})
	}
}

func TestCVEToOSV(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		r := testutils.SetupVCR(t)
		_ = r.GetDefaultClient()
		var cache git.RepoTagsCache
		cveData := loadTestData("CVE-2025-1110") // wire-server
		repos := []string{"https://gitlab.com/gitlab-org/gitlab"}
		refs := []cves.Reference{{Url: "https://gitlab.com/gitlab-org/gitlab"}}
		tempDir, err := os.MkdirTemp("", "osv-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		err = CVEToOSV(cveData, refs, repos, cache, tempDir)
		if err != nil {
			t.Fatalf("CVEToOSV() failed: %v", err)
		}

		expectedDir := filepath.Join(tempDir, "GitLab", "GitLab")
		expectedFile := filepath.Join(expectedDir, "CVE-2025-1110.json")

		if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
			t.Fatalf("Expected file %s was not created in %s", expectedFile, tempDir)
		}

		file, err := os.Open(expectedFile)
		if err != nil {
			t.Fatalf("Failed to open created file: %v", err)
		}
		defer file.Close()

		var osv vulns.Vulnerability
		if err := json.NewDecoder(file).Decode(&osv); err != nil {
			t.Fatalf("Failed to decode OSV json: %v", err)
		}

		if osv.ID != "CVE-2025-1110" {
			t.Errorf("Incorrect OSV ID, got %s, want CVE-2025-1110", osv.ID)
		}

		if len(osv.Affected) != 1 {
			t.Fatalf("Expected 1 affected package, got %d", len(osv.Affected))
		}

		affected := osv.Affected[0]
		if len(affected.Ranges) == 0 {
			t.Fatal("Expected ranges, but got none")
		}
	})

	t.Run("no repos", func(t *testing.T) {
		var cache git.RepoTagsCache
		cveData := loadTestData("CVE-2024-21634")
		tempDir, err := os.MkdirTemp("", "osv-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		err = CVEToOSV(cveData, []cves.Reference{}, []string{}, cache, tempDir)
		if err == nil {
			t.Errorf("Expected error for CVEToOSV with no repos, but got nil")
		}

		// Check that a notes file was created with the expected error.
		expectedNotesFile := filepath.Join(tempDir, "amazon-ion", "ion-java", "CVE-2024-21634.notes")
		if _, err := os.Stat(expectedNotesFile); os.IsNotExist(err) {
			t.Fatalf("Expected notes file %s was not created", expectedNotesFile)
		}

		notesContent, err := os.ReadFile(expectedNotesFile)
		if err != nil {
			t.Fatalf("Failed to read notes file: %v", err)
		}

		if !strings.Contains(string(notesContent), "No affected ranges detected") {
			t.Errorf("Expected notes file to contain 'No affected ranges' error, but it did not. Got: %s", string(notesContent))
		}
	})
}

func TestOutputOutcomes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "osv-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outcomes := map[cves.CVEID]ConversionOutcome{
		"CVE-2022-1234": Successful,
		"CVE-2022-5678": NoRepos,
	}
	reposForCVE := map[cves.CVEID][]string{
		"CVE-2022-1234": {"https://github.com/foo/bar"},
	}

	err = outputOutcomes(outcomes, reposForCVE, tempDir)
	if err != nil {
		t.Fatalf("outputOutcomes() failed: %v", err)
	}

	expectedFile := filepath.Join(tempDir, "outcomes.csv")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("Expected file %s was not created", expectedFile)
	}

	file, err := os.Open(expectedFile)
	if err != nil {
		t.Fatalf("Failed to open created file: %v", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	r := strings.NewReader(string(content))
	csvReader := csv.NewReader(r)
	records, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	expectedRecords := [][]string{
		{"CVE", "outcome", "repos"},
		{"CVE-2022-1234", "Successful", "https://github.com/foo/bar"},
		{"CVE-2022-5678", "NoRepos", ""},
	}

	if len(records) != len(expectedRecords) {
		t.Fatalf("Incorrect number of records, got %d, want %d", len(records), len(expectedRecords))
	}

	sort.Slice(records[1:], func(i, j int) bool {
		return records[i+1][0] < records[j+1][0]
	})
	sort.Slice(expectedRecords[1:], func(i, j int) bool {
		return expectedRecords[i+1][0] < expectedRecords[j+1][0]
	})

	if !reflect.DeepEqual(records, expectedRecords) {
		t.Errorf("Incorrect CSV content.\nGot:\n%v\nWant:\n%v", records, expectedRecords)
	}
}
