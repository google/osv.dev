// package main contains the conversion logic for turning debian security tracker info to OSV parts
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/vulnfeeds/conversion/writer"
	"github.com/google/osv.dev/vulnfeeds/faulttolerant"
	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultCvePath           = "cve_jsons"
	debianOutputPathDefault  = "debian-cve-osv"
	debianDistroInfoURL      = "https://debian.pages.debian.net/distro-info-data/debian.csv"
	debianSecurityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
	outputBucketDefault      = "debian-osv"
)

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	cvePath := flag.String("cve-path", defaultCvePath, "Path to CVE JSON files.")
	inputBucketName := flag.String("input-bucket", "", "The GCS bucket to download NVD CVE data from. If set, downloads data before processing.")

	debianOutputPath := flag.String("output-path", debianOutputPathDefault, "Path to output OSV files.")
	outputBucketName := flag.String("output-bucket", outputBucketDefault, "The GCS bucket to write to.")
	numWorkers := flag.Int("workers", 64, "Number of workers to process records")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If true, write to GCS bucket.")
	syncDeletions := flag.Bool("sync-deletions", false, "If false, do not delete files in bucket that are not local")
	flag.Parse()

	ctx := context.Background()

	if *inputBucketName != "" {
		logger.Info("Downloading NVD CVE data from GCS bucket", slog.String("bucket", *inputBucketName), slog.String("dest", *cvePath))
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create GCS client", slog.Any("err", err))
		}
		defer storageClient.Close()

		bkt := storageClient.Bucket(*inputBucketName)
		// TODO: It's inefficient to write all of this to a folder and then read it from the folder again.
		// It can just be 1 operation, and nothing should need to touch disk.
		if err := gcs.DownloadBucket(ctx, bkt, "nvd/", *cvePath); err != nil {
			logger.Fatal("Failed to download NVD CVE data from GCS", slog.Any("err", err))
		}

		logger.Info("Successfully downloaded NVD CVE data from GCS")
	}

	err := os.MkdirAll(*debianOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	vulnerabilities, err := buildDebianVulnerabilities(*cvePath)
	if err != nil {
		logger.Fatal("Failed to build Debian vulnerabilities", slog.Any("err", err))
	}
	runtime.GC()
	writer.UploadVulnsToGCS(ctx, "Debian CVEs", *uploadToGCS, *outputBucketName, "", *numWorkers, *debianOutputPath, vulnerabilities, *syncDeletions)
	logger.Info("Debian CVE conversion succeeded.")
}

func buildDebianVulnerabilities(cvePath string) ([]*osvschema.Vulnerability, error) {
	debianData, err := downloadDebianSecurityTracker()
	if err != nil {
		return nil, fmt.Errorf("failed to download/parse Debian Security Tracker json file: %w", err)
	}

	debianReleaseMap, err := getDebianReleaseMap()
	if err != nil {
		return nil, fmt.Errorf("failed to get Debian distro info data: %w", err)
	}

	targetCVEs := make(map[string]bool)
	for _, pkg := range debianData {
		for cveID := range pkg {
			if strings.HasPrefix(cveID, "CVE") {
				targetCVEs[cveID] = true
			}
		}
	}

	allCVEs := vulns.LoadTargetCVEMetadata(cvePath, targetCVEs)
	osvCVEs := generateOSVFromDebianTracker(debianData, debianReleaseMap, allCVEs)

	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(osvCVEs))
	for _, v := range osvCVEs {
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.Id), slog.String("id", v.Id))
			continue
		}
		vulnerabilities = append(vulnerabilities, v.Vulnerability)
	}

	return vulnerabilities, nil
}

// generateOSVFromDebianTracker converts Debian Security Tracker entries to OSV format.
func generateOSVFromDebianTracker(debianData DebianSecurityTrackerData, debianReleaseMap map[string]string, allCVEs map[models.CVEID]vulns.VulnerabilityMetadata) map[string]*vulns.Vulnerability {
	logger.Info("Converting Debian Security Tracker data to OSV.")
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
			currentNVDCVE := allCVEs[models.CVEID(cveID)]
			if !ok {
				v = &vulns.Vulnerability{
					Vulnerability: &osvschema.Vulnerability{
						Id:       "DEBIAN-" + cveID,
						Upstream: []string{cveID},
						Details:  cveData.Description,
						References: []*osvschema.Reference{
							{
								Type: osvschema.Reference_ADVISORY,
								Url:  "https://security-tracker.debian.org/tracker/" + cveID,
							},
						},
					},
				}

				if !currentNVDCVE.Published.IsZero() {
					v.Published = timestamppb.New(currentNVDCVE.Published)
				}

				if !currentNVDCVE.Modified.IsZero() {
					v.Modified = timestamppb.New(currentNVDCVE.Modified)
				} else if !currentNVDCVE.Published.IsZero() {
					v.Modified = timestamppb.New(currentNVDCVE.Published)
				}

				if currentNVDCVE.Metrics != nil {
					v.AddSeverity(currentNVDCVE.Metrics)
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
					pkgInfo.VersionInfo.AffectedVersions = []models.AffectedVersion{{Introduced: "0"}, {Fixed: release.FixedVersion}}
				} else {
					pkgInfo.VersionInfo.AffectedVersions = []models.AffectedVersion{{Introduced: "0"}}
				}

				if len(pkgInfo.VersionInfo.AffectedVersions) > 0 {
					v.AddPkgInfo(pkgInfo)
				}
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

	logger.Info("Successfully downloaded Debian Security Tracker Data")

	return decodedDebianData, err
}
