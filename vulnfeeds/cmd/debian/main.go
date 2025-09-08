// package main contains the conversion logic for turning debian security tracker info to OSV parts
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"

	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/faulttolerant"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	defaultCvePath           = "cve_jsons"
	debianOutputPathDefault  = "debian-cve-osv"
	debianDistroInfoURL      = "https://debian.pages.debian.net/distro-info-data/debian.csv"
	debianSecurityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
)

func main() {
	var logCleanup = logger.InitGlobalLogger("debian-osv", false)
	defer logCleanup()

	debianOutputPath := flag.String("output_path", debianOutputPathDefault, "Path to output OSV files.")
	flag.Parse()

	err := os.MkdirAll(*debianOutputPath, 0755)
	if err != nil {
		logger.Fatalf("Can't create output path: %s", err)
	}

	debianData, err := downloadDebianSecurityTracker()
	if err != nil {
		logger.Fatalf("Failed to download/parse Debian Security Tracker json file: %s", err)
	}

	debianReleaseMap, err := getDebianReleaseMap()
	if err != nil {
		logger.Fatalf("Failed to get Debian distro info data: %s", err)
	}

	allCVEs := vulns.LoadAllCVEs(defaultCvePath)
	osvCves := generateOSVFromDebianTracker(debianData, debianReleaseMap, allCVEs)

	if err = writeToOutput(osvCves, *debianOutputPath); err != nil {
		logger.Fatalf("Failed to write OSV output file: %s", err)
	}

	logger.Infof("Debian CVE conversion succeeded.")
}

// generateOSVFromDebianTracker converts Debian Security Tracker entries to OSV format.
func generateOSVFromDebianTracker(debianData DebianSecurityTrackerData, debianReleaseMap map[string]string, allCVEs map[cves.CVEID]cves.Vulnerability) map[string]*vulns.Vulnerability {
	logger.Infof("Converting Debian Security Tracker data to OSV.")
	osvCves := make(map[string]*vulns.Vulnerability)

	// Sorts packages to ensure results remain consistent between runs.
	pkgNames := make([]string, 0, len(debianData))
	for name := range debianData {
		pkgNames = append(pkgNames, name)
	}
	sort.Strings(pkgNames)

	// Sorts releases to ensure pkgInfos remain consistent between runs.
	releaseNames := make([]string, 0, len(debianReleaseMap))
	for k := range debianReleaseMap {
		releaseNames = append(releaseNames, k)
	}

	sort.Slice(releaseNames, func(i, j int) bool {
		vi, _ := strconv.ParseFloat(debianReleaseMap[releaseNames[i]], 64)
		vj, _ := strconv.ParseFloat(debianReleaseMap[releaseNames[j]], 64)

		return vi < vj
	})

	for _, pkgName := range pkgNames {
		pkg := debianData[pkgName]
		for cveID, cveData := range pkg {
			// Debian Security Tracker has some 'TEMP-' Records we don't want to convert
			if !strings.HasPrefix(cveID, "CVE") {
				continue
			}
			v, ok := osvCves[cveID]
			if !ok {
				v = &vulns.Vulnerability{
					Vulnerability: osvschema.Vulnerability{
						ID:        "DEBIAN-" + cveID,
						Upstream:  []string{cveID},
						Modified:  time.Now().UTC(),
						Published: allCVEs[cves.CVEID(cveID)].CVE.Published.Time,
						Details:   cveData.Description,
						References: []osvschema.Reference{
							{
								Type: "ADVISORY",
								URL:  "https://security-tracker.debian.org/tracker/" + cveID,
							},
						},
					},
				}
				osvCves[cveID] = v
			}

			for _, releaseName := range releaseNames {
				// For reference on urgency levels, see: https://security-team.debian.org/security_tracker.html#severity-levels
				release, ok := cveData.Releases[releaseName]
				if !ok {
					continue
				}
				debianVersion, ok := debianReleaseMap[releaseName]
				if !ok {
					continue
				}

				if release.Status == "resolved" && release.FixedVersion == "0" { // not affected
					continue
				}

				pkgInfo := vulns.PackageInfo{
					PkgName:   pkgName,
					Ecosystem: "Debian:" + debianVersion,
					EcosystemSpecific: map[string]any{
						"urgency": release.Urgency,
					},
				}

				if release.Status == "resolved" {
					pkgInfo.VersionInfo.AffectedVersions = []models.AffectedVersion{{Fixed: release.FixedVersion}}
				}
				v.AddPkgInfo(pkgInfo)
			}
		}
	}

	return osvCves
}

// getDebianReleaseMap gets the Debian version number, excluding testing and experimental versions.
func getDebianReleaseMap() (map[string]string, error) {
	releaseMap := make(map[string]string)
	res, err := faulttolerant.Get(debianDistroInfoURL)
	if err != nil {
		return releaseMap, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return releaseMap, fmt.Errorf("HTTP request failed: %s", res.Status)
	}

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
		switch col {
		case "version":
			versionIndex = i
		case "series":
			seriesIndex = i
		}
	}

	if seriesIndex == -1 || versionIndex == -1 {
		return releaseMap, err
	}

	for _, row := range data[1:] {
		if row[versionIndex] == "" {
			continue
		}
		releaseMap[row[seriesIndex]] = row[versionIndex]
	}

	return releaseMap, err
}

func writeToOutput(osvCves map[string]*vulns.Vulnerability, debianOutputPath string) error {
	logger.Infof("Writing OSV files to the output.")
	for cveID, osv := range osvCves {
		if len(osv.Affected) == 0 {
			logger.Warnf("Skipping DEBIAN-%s as no affected versions found.", cveID)
			continue
		}
		file, err := os.OpenFile(path.Join(debianOutputPath, "DEBIAN-"+cveID+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(osv)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}

	return nil
}

// downloadDebianSecurityTracker download Debian json file
func downloadDebianSecurityTracker() (DebianSecurityTrackerData, error) {
	res, err := faulttolerant.Get(debianSecurityTrackerURL)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed: %s", res.Status)
	}

	var decodedDebianData DebianSecurityTrackerData

	if err := json.NewDecoder(res.Body).Decode(&decodedDebianData); err != nil {
		return nil, err
	}

	logger.Infof("Successfully downloaded Debian Security Tracker Data.")

	return decodedDebianData, err
}
