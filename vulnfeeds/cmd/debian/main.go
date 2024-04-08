package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	debianOutputPathDefault  = "parts/debian"
	debianDistroInfoURL      = "https://debian.pages.debian.net/distro-info-data/debian.csv"
	debianSecurityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
)

var Logger utility.LoggerWrapper

func main() {
	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("debian-osv")
	defer logCleanup()

	err := os.MkdirAll(debianOutputPathDefault, 0755)
	if err != nil {
		Logger.Fatalf("Can't create output path: %s", err)
	}

	debianData, err := downloadDebianSecurityTracker()
	if err != nil {
		Logger.Fatalf("Failed to download/parse Debian Security Tracker json file: %s", err)
	}

	debianReleaseMap, err := getDebianReleaseMap()
	if err != nil {
		Logger.Fatalf("Failed to get Debian distro info data: %s", err)
	}

	cvePkgInfos := generateDebianSecurityTrackerOSV(debianData, debianReleaseMap)
	if err = writeToOutput(cvePkgInfos); err != nil {
		Logger.Fatalf("Failed to write OSV output file: %s", err)
	}
}

// getDebianReleaseMap gets the Debian version number, excluding testing and experimental versions.
func getDebianReleaseMap() (map[string]string, error) {
	releaseMap := make(map[string]string)
	res, err := http.Get(debianDistroInfoURL)
	if err != nil {
		return releaseMap, err
	}
	defer res.Body.Close()

	reader := csv.NewReader(res.Body)
	reader.FieldsPerRecord = -1
	data, err := reader.ReadAll()
	if err != nil {
		return releaseMap, err
	}

	versionIndex := -1
	seriesIndex := -1

	// Get the index number of version and series.
	for i, col := range data[0] {
		if col == "version" {
			versionIndex = i
		} else if col == "series" {
			seriesIndex = i
		}
	}

	if seriesIndex == -1 || versionIndex == -1 {
		return releaseMap, err
	}

	for _, row := range data[1:] {
		if row[seriesIndex] == "experimental" || row[seriesIndex] == "sid" {
			continue
		}

		releaseMap[row[seriesIndex]] = row[versionIndex]
	}

	return releaseMap, err
}

// updateOSVPkgInfos adds new release entries to osvPkgInfos.
func updateOSVPkgInfos(pkgName string, cveId string, releases map[string]Release, osvPkgInfos map[string][]vulns.PackageInfo, debianReleaseMap map[string]string) {
	var pkgInfos []vulns.PackageInfo
	if value, ok := osvPkgInfos[cveId]; ok {
		pkgInfos = value
	}
	for releaseName, release := range releases {
		// Skips 'not yet assigned' entries because their status may change in the future.
		// For reference on urgency levels, see: https://security-team.debian.org/security_tracker.html#severity-levels
		if release.Urgency == "not yet assigned" {
			continue
		}
		debianVersion, ok := debianReleaseMap[releaseName]
		if !ok {
			continue
		}

		pkgInfo := vulns.PackageInfo{
			PkgName:   pkgName,
			Ecosystem: "Debian:" + debianVersion,
		}
		pkgInfo.EcosystemSpecific = make(map[string]string)

		if release.Status == "resolved" {
			if release.FixedVersion == "0" { // not affected
				continue
			}
			pkgInfo.VersionInfo = cves.VersionInfo{
				AffectedVersions: []cves.AffectedVersion{{Fixed: release.FixedVersion}},
			}
		}
		pkgInfo.EcosystemSpecific["urgency"] = release.Urgency
		pkgInfos = append(pkgInfos, pkgInfo)
	}
	if pkgInfos != nil {
		osvPkgInfos[cveId] = pkgInfos
	}
}

// generateDebianSecurityTrackerOSV converts Debian Security Tracker entries to OSV PackageInfo format.
func generateDebianSecurityTrackerOSV(debianData DebianSecurityTrackerData, debianReleaseMap map[string]string) map[string][]vulns.PackageInfo {
	osvPkgInfos := make(map[string][]vulns.PackageInfo)
	for pkgName, pkg := range debianData {
		for cveId, cve := range pkg {
			updateOSVPkgInfos(pkgName, cveId, cve.Releases, osvPkgInfos, debianReleaseMap)
		}
	}

	return osvPkgInfos
}

func writeToOutput(cvePkgInfos map[string][]vulns.PackageInfo) error {
	for cveId := range cvePkgInfos {
		pkgInfos := cvePkgInfos[cveId]
		file, err := os.OpenFile(path.Join(debianOutputPathDefault, cveId+".debian.json"), os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(&pkgInfos)
		if err != nil {
			return err
		}
		_ = file.Close()
	}

	return nil
}

// downloadDebianSecurityTracker download Debian json file
func downloadDebianSecurityTracker() (DebianSecurityTrackerData, error) {
	res, err := http.Get(debianSecurityTrackerURL)
	if err != nil {
		return nil, err
	}

	var decodedDebianData DebianSecurityTrackerData

	if err := json.NewDecoder(res.Body).Decode(&decodedDebianData); err != nil {
		return nil, err
	}

	return decodedDebianData, err
}
