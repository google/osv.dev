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
	debianSecurityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
	debianOutputPathDefault  = "parts/debian"
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

	debianData := downloadDebianSecurityTracker()
	cvePkgInfos := generateDebianSecurityTrackerOSV(debianData)
	writeToOutput(cvePkgInfos)
}

// Gets the Debian version number, excluding sid and experimental versions.
func getDebianReleaseMap() map[string]string {
	releaseMap := make(map[string]string)
	res, err := http.Get("https://debian.pages.debian.net/distro-info-data/debian.csv")
	if err != nil {
		Logger.Fatalf("Failed to get Debian release info data: %s", err)
	}
	defer res.Body.Close()

	reader := csv.NewReader(res.Body)
	reader.FieldsPerRecord = -1
	data, err := reader.ReadAll()
	if err != nil {
		Logger.Fatalf("Failed to load Debian release info csv: %s", err)
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
		Logger.Fatalf("Failed to get Debian release info: %s", err)
	}

	for _, row := range data[1:] {
		if row[seriesIndex] == "experimental" || row[seriesIndex] == "sid" {
			continue
		}

		releaseMap[row[seriesIndex]] = row[versionIndex]
	}

	return releaseMap
}

// Convert Debian Security Tracker entries to OSV PackageInfo format.
func generateDebianSecurityTrackerOSV(debianData DebianSecurityTrackerData) map[string][]vulns.PackageInfo {
	debianReleaseMap := getDebianReleaseMap()
	osvPkgInfos := make(map[string][]vulns.PackageInfo)
	for pkgName, pkg := range debianData {
		for cveId, cve := range pkg {
			var pkgInfos []vulns.PackageInfo
			if value, ok := osvPkgInfos[cveId]; ok {
				pkgInfos = value
			}

			for releaseName, release := range cve.Releases {
				if release.Urgency == "not yet assigned" || release.Urgency == "end-of-life" {
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
	}

	return osvPkgInfos
}

func writeToOutput(cvePkgInfos map[string][]vulns.PackageInfo) {
	for cveId := range cvePkgInfos {
		pkgInfos := cvePkgInfos[cveId]
		file, err := os.OpenFile(path.Join(debianOutputPathDefault, cveId+".debian.json"), os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			Logger.Fatalf("Failed to create/write osv output file: %s", err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(&pkgInfos)
		if err != nil {
			Logger.Fatalf("Failed to encode package info output file: %s", err)
		}
		_ = file.Close()
	}
}

// Download json file
func downloadDebianSecurityTracker() DebianSecurityTrackerData {
	res, err := http.Get(debianSecurityTrackerURL)
	if err != nil {
		Logger.Fatalf("Failed to get Debian Security Tracker json: %s", err)
	}

	var decodedDebianData DebianSecurityTrackerData

	if err := json.NewDecoder(res.Body).Decode(&decodedDebianData); err != nil {
		Logger.Fatalf("Failed to parse debian json: %s", err)
	}

	return decodedDebianData
}
