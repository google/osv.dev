package main

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"golang.org/x/exp/maps"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
)

func loadTestData(cveName string) cves.CVEItem {
	file, err := os.Open("../../test_data/nvdcve-1.1-test-data.json")
	if err != nil {
		log.Fatalf("Failed to load test data")
	}
	var nvdCves cves.NVDCVE
	json.NewDecoder(file).Decode(&nvdCves)
	for _, item := range nvdCves.CVEItems {
		if item.CVE.CVEDataMeta.ID == cveName {
			return item
		}
	}
	log.Fatalf("test data doesn't contain specified CVE")
	return cves.CVEItem{}
}

func TestLoadParts(t *testing.T) {
	allParts := loadParts("../../test_data/parts")
	expectedPartCount := 12
	actualPartCount := len(allParts)

	if actualPartCount != expectedPartCount {
		t.Errorf("Expected %d entries, got %d entries: %#v", expectedPartCount, actualPartCount, maps.Keys(allParts))
	}

	tests := map[string]struct {
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
	cveStuff := map[string]cves.CVEItem{
		"CVE-2022-33745": loadTestData("CVE-2022-33745"),
		"CVE-2022-32746": loadTestData("CVE-2022-32746"),
	}
	allParts := loadParts("../../test_data/parts")

	combinedOSV := combineIntoOSV(cveStuff, allParts, "")

	expectedCombined := 2
	actualCombined := len(combinedOSV)

	if actualCombined != expectedCombined {
		t.Errorf("Expected %d in combination, got %d: %#v", expectedCombined, actualCombined, combinedOSV)
	}
	for cve := range cveStuff {
		if len(combinedOSV[cve].Affected) != len(allParts[cve]) {
			t.Errorf("Affected lengths for %s do not match", cve)
		}
	}
}
