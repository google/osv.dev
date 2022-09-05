package main

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/google/osv/vulnfeeds/cves"
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

func sliceEqual[K comparable](a []K, b []K) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLoadParts(t *testing.T) {
	allParts := loadParts("../../test_data/parts")

	if len(allParts) != 10 {
		t.Errorf("Expected 10 entries, got %d entries", len(allParts["Alpine"]))
	}

	hasCve := 0
	for id, v := range allParts {
		if id == "CVE-2015-9251" {
			if len(v) != 1 {
				t.Errorf("Expected 1 alpine entry for CVE-2015-9251, got %d entries", len(v))
			}
			if v[0].Ecosystem != "Alpine:v3.10" {
				t.Errorf("Expected ecosystem to be: Alpine:v3.10, got %s.", v[0].Ecosystem)
			}
			hasCve++
		}
		if id == "CVE-2016-2176" {
			if len(v) != 7 {
				t.Errorf("Expected 7 alpine entries for CVE-2016-2176, got %d entries", len(v))
			}
			hasCve++
		}
	}

	if hasCve != 2 {
		t.Errorf("Expected CVEs does not exist")
	}
}

func TestCombineIntoOSV(t *testing.T) {
	cveStuff := map[string]cves.CVEItem{
		"CVE-2022-33745": loadTestData("CVE-2022-33745"),
	}
	allParts := loadParts("../../test_data/parts")

	combinedOsv := combineIntoOSV(cveStuff, allParts)
	if len(combinedOsv) != 1 {
		t.Errorf("Expected 1 combination, got %v", combinedOsv)
	}
	if len(combinedOsv["CVE-2022-33745"].Affected) != len(allParts["CVE-2022-33745"]) {
		t.Errorf("Affected lengths do not match")
	}
}
