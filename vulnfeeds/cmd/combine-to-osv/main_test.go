package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"testing"
	"time"

	"maps"

	"github.com/google/osv/vulnfeeds/cves"
	gitpurl "github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func loadTestData2(cveName string) cves.Vulnerability {
	fileName := fmt.Sprintf("../../test_data/nvdcve-2.0/%s.json", cveName)
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to load test data from %q: %#v", fileName, err)
	}
	var nvdCves cves.CVEAPIJSON20Schema
	err = json.NewDecoder(file).Decode(&nvdCves)
	if err != nil {
		log.Fatalf("Failed to decode %q: %+v", fileName, err)
	}
	for _, vulnerability := range nvdCves.Vulnerabilities {
		if string(vulnerability.CVE.ID) == cveName {
			return vulnerability
		}
	}
	log.Fatalf("test data doesn't contain %q", cveName)

	return cves.Vulnerability{}
}

func TestLoadParts(t *testing.T) {
	allParts, _ := loadParts("../../test_data/parts")
	expectedPartCount := 15
	actualPartCount := len(allParts)

	if actualPartCount != expectedPartCount {
		t.Errorf("Expected %d entries, got %d entries: %#v", expectedPartCount, actualPartCount, slices.Collect(maps.Keys(allParts)))
	}

	tests := map[cves.CVEID]struct {
		ecosystems []string
	}{
		"CVE-2015-9251": {
			ecosystems: []string{"Alpine:v3.10"},
		},
		"CVE-2016-2176": {
			ecosystems: []string{
				"Alpine:v3.2",
				"Alpine:v3.3",
				"Alpine:v3.4",
				"Alpine:v3.5",
				"Alpine:v3.6",
				"Alpine:v3.7",
				"Alpine:v3.8",
				"", // NVD converted CVEs have no ecosystem
			},
		},
	}

	hasCve := 0
	for id, v := range allParts {
		if elem, ok := tests[id]; ok {
			var ecosystemArray []string
			for _, elem := range v {
				ecosystemArray = append(ecosystemArray, elem.Ecosystem)
			}
			if !utility.SliceEqualUnordered(elem.ecosystems, ecosystemArray) {
				t.Errorf("Expected ecosystem for %s to have: %#v, got %#v.", id, elem.ecosystems, ecosystemArray)
			}
			hasCve++
		}
	}

	if hasCve != len(tests) {
		t.Errorf("Expected CVEs do not exist")
	}
}

func TestCombineIntoOSV(t *testing.T) {
	cveStuff := map[cves.CVEID]cves.Vulnerability{
		"CVE-2022-33745":   loadTestData2("CVE-2022-33745"),
		"CVE-2022-32746":   loadTestData2("CVE-2022-32746"),
		"CVE-2018-1000500": loadTestData2("CVE-2018-1000500"),
	}
	allParts, cveModifiedTime := loadParts("../../test_data/parts")

	combinedOSV := combineIntoOSV(cveStuff, allParts, "", cveModifiedTime)

	expectedCombined := 3
	actualCombined := len(combinedOSV)

	if actualCombined != expectedCombined {
		t.Errorf("Expected %d in combination, got %d: %#v", expectedCombined, actualCombined, combinedOSV)
	}
	for cve := range cveStuff {
		if len(combinedOSV[cve].Affected) != len(allParts[cve]) {
			t.Errorf("Affected lengths for %s do not match", cve)
		}
		found := false
		switch cve {
		case "CVE-2018-1000500":
			for _, reference := range combinedOSV[cve].References {
				if reference.Type == "ADVISORY" &&
					reference.URL == "https://security-tracker.debian.org/tracker/CVE-2018-1000500" {
					found = true
				}
			}
		case "CVE-2022-33745":
			for _, reference := range combinedOSV[cve].References {
				if reference.Type == "ADVISORY" &&
					reference.URL == "https://security.alpinelinux.org/vuln/CVE-2022-33745" {
					found = true
				}
			}
		case "CVE-2022-32746":
			for _, reference := range combinedOSV[cve].References {
				if reference.Type == "ADVISORY" &&
					reference.URL == "https://security.alpinelinux.org/vuln/CVE-2022-32746" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s doesn't have all expected references", cve)
		}
	}
}

func TestGetModifiedTime(t *testing.T) {
	_, err := getModifiedTime("../../test_data/parts/debian/CVE-2016-1585.debian.json")
	if err != nil {
		t.Errorf("Failed to get modified time.")
	}
}

func TestUpdateModifiedDate(t *testing.T) {
	var cveID1, cveID2 cves.CVEID
	cveID1 = "CVE-2022-33745"
	cveID2 = "CVE-2022-32746"

	cveStuff := map[cves.CVEID]cves.Vulnerability{
		cveID1: loadTestData2("CVE-2022-33745"),
		cveID2: loadTestData2("CVE-2022-32746"),
	}
	allParts, _ := loadParts("../../test_data/parts")

	cveModifiedTimeMock := make(map[cves.CVEID]time.Time)
	time1 := "0001-00-00T00:00:00Z"
	time2 := "2024-04-30T00:38:53Z"
	modifiedTime1, _ := time.Parse(time.RFC3339, time1)
	modifiedTime2, _ := time.Parse(time.RFC3339, time2)
	cveModifiedTimeMock[cveID1] = modifiedTime1
	cveModifiedTimeMock[cveID2] = modifiedTime2

	combinedOSV := combineIntoOSV(cveStuff, allParts, "", cveModifiedTimeMock)

	expectedCombined := 2
	actualCombined := len(combinedOSV)

	if actualCombined != expectedCombined {
		t.Errorf("Expected %d in combination, got %d: %#v", expectedCombined, actualCombined, combinedOSV)
	}

	// Keeps CVE modified time if none of its parts have a later modification time
	if combinedOSV[cveID1].Modified.Equal(modifiedTime1) {
		t.Errorf("Wrong modified time: %s", combinedOSV["CVE-2022-33745"].Modified)
	}

	// Updates the CVE's modified time if any of its parts have a later modification time
	if combinedOSV[cveID2].Modified != modifiedTime2 {
		t.Errorf("Wrong modified time, expected: %s, got: %s", time2, combinedOSV["CVE-2022-32746"].Modified)
	}
}

func TestRepoURLFromRanges_GIT(t *testing.T) {
	t.Parallel()

	ranges := []osvschema.Range{
		{
			Type: "GIT",
			Repo: "https://github.com/eclipse-openj9/openj9",
			Events: []osvschema.Event{
				{Introduced: "0"},
			},
		},
	}
	got := repoURLFromRanges(ranges)
	want := "https://github.com/eclipse-openj9/openj9"
	if got != want {
		t.Fatalf("repoURLFromRanges() = %q, want %q", got, want)
	}
}

func TestRepoURLFromRanges_NoGIT(t *testing.T) {
	t.Parallel()

	ranges := []osvschema.Range{
		{
			Type: "ECOSYSTEM",
			Events: []osvschema.Event{
				{Introduced: "0"},
				{Fixed: "1.2.3"},
			},
		},
	}
	if got := repoURLFromRanges(ranges); got != "" {
		t.Fatalf("repoURLFromRanges() = %q, want empty", got)
	}
}

func TestAddVersionedRepoPURLs_FromVersions(t *testing.T) {
	t.Setenv("ENABLE_REPO_PURL_TAGS", "") // ensure derivation path is off

	repo := "https://github.com/chriskohlhoff/asio"
	aff := &osvschema.Affected{
		Package:  osvschema.Package{Ecosystem: "GIT", Name: "asio"},
		Versions: []string{"asio-1-13-0", "asio-1-12-0"},
		Ranges:   []osvschema.Range{{Type: "GIT", Repo: repo, Events: []osvschema.Event{{Introduced: "0"}}}},
	}

	addVersionedRepoPURLs(aff, repo)

	base, err := gitpurl.BuildGenericRepoPURL(repo)
	if err != nil || base == "" {
		t.Fatalf("failed to build base purl: %v", err)
	}

	ds := aff.DatabaseSpecific
	list, ok := ds["repo_purls"].([]string)
	if !ok || len(list) == 0 {
		t.Fatalf("repo_purls missing/empty: %#v", ds)
	}

	want1 := base + "@asio-1-13-0"
	want2 := base + "@asio-1-12-0"
	found1, found2 := false, false
	for _, p := range list {
		if p == want1 {
			found1 = true
		}
		if p == want2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("missing expected entries, got %#v", list)
	}
}
