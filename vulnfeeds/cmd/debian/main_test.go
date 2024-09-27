package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/osv/vulnfeeds/vulns"
)

func Test_generateDebianSecurityTrackerOSV(t *testing.T) {
	var decodedDebianData DebianSecurityTrackerData

	file, _ := os.Open("../../test_data/debian/debian_security_tracker_mock.json")
	defer file.Close()
	_ = json.NewDecoder(file).Decode(&decodedDebianData)

	debianReleaseMap := make(map[string]string)
	debianReleaseMap["sarge"] = "3.1"
	debianReleaseMap["stretch"] = "9"
	debianReleaseMap["buster"] = "10"
	debianReleaseMap["bullseye"] = "11"
	debianReleaseMap["bookworm"] = "12"
	debianReleaseMap["trixie"] = "13"

	osvPkgInfos := generateDebianSecurityTrackerOSV(decodedDebianData, debianReleaseMap)
	expectedCount := 3
	if len(osvPkgInfos) != expectedCount {
		t.Errorf("Expected %v Debian OSV entries , got %v", expectedCount, osvPkgInfos)
	}
	for cveId, pkgInfos := range osvPkgInfos {
		file, err := os.Open(fmt.Sprintf("../../test_data/parts/debian/%s.debian.json", cveId))
		if err != nil {
			t.Errorf("../../test_data/parts/debian/%s.debian.json doesn't exist", cveId)
		}
		expectedResult, _ := io.ReadAll(file)
		var expectedPackageInfos []vulns.PackageInfo
		json.Unmarshal(expectedResult, &expectedPackageInfos)
		if len(pkgInfos) != len(expectedPackageInfos) || pkgInfos[0].EcosystemSpecific["urgency"] != expectedPackageInfos[0].EcosystemSpecific["urgency"] {
			t.Errorf("Expected Debian OSV data %v, got %v", expectedPackageInfos, pkgInfos)
		}
	}
}
