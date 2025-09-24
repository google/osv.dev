// package main contains the conversion logic for turning debian security tracker info to OSV parts
package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
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
	outputBucketDefault      = "debian-osv"
	hashMetadataKey          = "sha256-hash"
)

func main() {
	logger.InitGlobalLogger()

	debianOutputPath := flag.String("output_path", debianOutputPathDefault, "Path to output OSV files.")
	outputBucketName := flag.String("output_bucket", outputBucketDefault, "The GCS bucket to write to.")
	numWorkers := flag.Int("num_workers", 64, "Number of workers to process records")
	dryRun := flag.Bool("dry_run", false, "If true, do not write to GCS bucket and instead write to local disk.")
	flag.Parse()

	err := os.MkdirAll(*debianOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	debianData, err := downloadDebianSecurityTracker()
	if err != nil {
		logger.Fatal("Failed to download/parse Debian Security Tracker json file", slog.Any("err", err))
	}

	debianReleaseMap, err := getDebianReleaseMap()
	if err != nil {
		logger.Fatal("Failed to get Debian distro info data", slog.Any("err", err))
	}

	allCVEs := vulns.LoadAllCVEs(defaultCvePath)

	ctx := context.Background()
	var bkt *storage.BucketHandle
	if !*dryRun {
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create storage client", slog.Any("err", err))
		}
		bkt = storageClient.Bucket(*outputBucketName)
	}

	var wg sync.WaitGroup
	vulnChan := make(chan *vulns.Vulnerability)

	for range *numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, vulnChan, bkt, *debianOutputPath)
		}()
	}

	osvCVEs := generateOSVFromDebianTracker(debianData, debianReleaseMap, allCVEs)

	for _, v := range osvCVEs {
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", v.ID), slog.String("id", v.ID))
			continue
		}
		vulnChan <- v
	}
	close(vulnChan)
	wg.Wait()

	logger.Info("Debian CVE conversion succeeded.")
}

func worker(ctx context.Context, vulnChan <-chan *vulns.Vulnerability, bkt *storage.BucketHandle, outputDir string) {
	isDryRun := bkt == nil
	for v := range vulnChan {
		debianID := v.ID
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", debianID), slog.String("id", debianID))
			continue
		}

		// Marshal before setting modified time to generate hash.
		buf, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			logger.Error("failed to marshal vulnerability", slog.String("id", debianID), slog.Any("err", err))
			continue
		}

		objName := path.Join(outputDir, debianID+".json")

		if isDryRun {
			logger.Info("Dry run: writing to local disk", slog.String("path", objName))
			v.Modified = time.Now().UTC()
			buf, err = json.MarshalIndent(v, "", "  ")
			if err != nil {
				logger.Error("failed to marshal vulnerability with modified time", slog.String("id", debianID), slog.Any("err", err))
				continue
			}
			if err := os.WriteFile(objName, buf, 0644); err != nil {
				logger.Error("failed to write file in dry run", slog.String("path", objName), slog.Any("err", err))
			}
			continue
		}

		hash := sha256.Sum256(buf)
		hexHash := hex.EncodeToString(hash[:])

		obj := bkt.Object(objName)

		// Check if object exists and if hash matches.
		attrs, err := obj.Attrs(ctx)
		if err == nil {
			// Object exists, check hash.
			if attrs.Metadata != nil && attrs.Metadata[hashMetadataKey] == hexHash {
				logger.Info("Skipping upload, hash matches", slog.String("id", debianID))
				continue
			}
		} else if !errors.Is(err, storage.ErrObjectNotExist) {
			logger.Error("failed to get object attributes", slog.String("id", debianID), slog.Any("err", err))
			continue
		}

		// Object does not exist or hash differs, upload.
		v.Modified = time.Now().UTC()
		buf, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			logger.Error("failed to marshal vulnerability with modified time", slog.String("id", debianID), slog.Any("err", err))
			continue
		}

		logger.Info("Uploading", slog.String("id", debianID))
		wc := obj.NewWriter(ctx)
		wc.Metadata = map[string]string{
			hashMetadataKey: hexHash,
		}
		wc.ContentType = "application/json"

		if _, err := wc.Write(buf); err != nil {
			logger.Error("failed to write to GCS object", slog.String("id", debianID), slog.Any("err", err))
			// Try to close writer even if write failed.
			if closeErr := wc.Close(); closeErr != nil {
				logger.Error("failed to close GCS writer after write error", slog.String("id", debianID), slog.Any("err", closeErr))
			}

			continue
		}

		if err := wc.Close(); err != nil {
			logger.Error("failed to close GCS writer", slog.String("id", debianID), slog.Any("err", err))
			continue
		}
	}
}

// generateOSVFromDebianTracker converts Debian Security Tracker entries to OSV format.
func generateOSVFromDebianTracker(debianData DebianSecurityTrackerData, debianReleaseMap map[string]string, allCVEs map[cves.CVEID]cves.Vulnerability) map[string]*vulns.Vulnerability {
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
			if !ok {
				v = &vulns.Vulnerability{
					Vulnerability: osvschema.Vulnerability{
						ID:        "DEBIAN-" + cveID,
						Upstream:  []string{cveID},
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
