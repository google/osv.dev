package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
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
	refs := identifyPossibleURLs(cveData)

	v, notes := vulns.FromCVE5(cveData, refs)

	if v.ID != "CVE-2021-44228" {
		t.Errorf("Expected ID CVE-2021-44228, got %s", v.ID)
	}

	if !strings.HasPrefix(v.Details, "Apache Log4j2") {
		t.Errorf("Details do not seem correct, got: %s", v.Details)
	}

	expectedPublished, _ := time.Parse(time.RFC3339, "2021-12-10T00:00:00Z")
	if v.Published != expectedPublished {
		t.Errorf("Published date is incorrect, got: %s, want: %s", v.Published, expectedPublished)
	}

	expectedModified, _ := time.Parse(time.RFC3339, "2025-02-04T14:25:37Z")
	if v.Modified.Truncate(time.Second) != expectedModified {
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
			got, _ := ExtractVersionInfo(cveData, repos, client)

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

		})
	}
}
