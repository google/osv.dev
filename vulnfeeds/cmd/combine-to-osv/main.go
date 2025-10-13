// package main combines CVEs and security advisories into OSV records.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"slices"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/upload"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/iterator"
)

const (
	defaultOSVOutputPath = "osv-output"
	defaultCVE5Path      = "cve5"
	defaultNVDOSVPath    = "nvd"
)

func main() {
	logger.InitGlobalLogger()

	cve5Path := flag.String("cve5Path", defaultCVE5Path, "Path to CVE5 OSV files")
	nvdPath := flag.String("nvdPath", defaultNVDOSVPath, "Path to NVD OSV files")
	osvOutputPath := flag.String("osvOutputPath", defaultOSVOutputPath, "Local output path of combined OSV files, or GCS prefix if uploading.")
	outputBucketName := flag.String("output_bucket", "cve-osv-conversion", "The GCS bucket to write to.")
	overridesBucketName := flag.String("overrides_bucket", "cve-osv-conversion", "The GCS bucket to read overrides from.")
	uploadToGCS := flag.Bool("uploadToGCS", false, "If true, upload to GCS bucket instead of writing to local disk.")
	numWorkers := flag.Int("num_workers", 64, "Number of workers to process records")
	flag.Parse()

	err := os.MkdirAll(*osvOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	// Load CVE5 OSVs
	allCVE5 := loadOSV(*cve5Path)
	// Load NVD OSVs
	allNVD := loadOSV(*nvdPath)
	debianCVEs, err := listBucketObjects("osv-test-debian-osv", "/debian-cve-osv")
	if err != nil {
		logger.Warn("Failed to list debian cves", slog.Any("err", err))
	} else {
		for i, filename := range debianCVEs {
			cve := extractCVEName(filename, "DEBIAN-")
			if cve != "" {
				debianCVEs[i] = cve
			}
		}
	}

	// run extract file name on each element in debianCVEs and alpineCVEs.
	alpineCVEs, err := listBucketObjects("osv-test-cve-osv-conversion", "/alpine")
	if err != nil {
		logger.Warn("Failed to list alpine cves", slog.Any("err", err))
	} else {
		for i, filename := range alpineCVEs {
			cve := extractCVEName(filename, "ALPINE-")
			if cve != "" {
				alpineCVEs[i] = cve
			}
		}
	}

	// this ensures the creation of CVEs even if they don't have packages
	// to ensure Alpine and Debian CVEs have an upstream CVE.
	// linter is compaining that we aren't appending to the same slice, but we
	// just want to combine these two arrays with a more descriptive name.
	mandatoryCVEIDs := append(debianCVEs, alpineCVEs...) //nolint:gocritic
	combinedData := combineIntoOSV(allCVE5, allNVD, mandatoryCVEIDs)

	ctx := context.Background()

	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(combinedData))
	for _, v := range combinedData {
		vulnerabilities = append(vulnerabilities, &v)
	}

	upload.Upload(ctx, "OSV files", *uploadToGCS, *outputBucketName, *overridesBucketName, *numWorkers, *osvOutputPath, vulnerabilities)
}

// extractCVEName extracts the CVE name from a given filename and prefix.
// It returns an empty string if the filename does not start with "CVE".
func extractCVEName(filename string, prefix string) string {
	cleaned := strings.TrimPrefix(filename, prefix)
	cleaned = strings.TrimSuffix(cleaned, ".json")
	pre := strings.SplitAfter(cleaned, "-")
	if pre[0] != "CVE" {
		return ""
	}

	return cleaned
}

// listBucketObjects lists the names of all objects in a Google Cloud Storage bucket.
// It does not download the file contents.
func listBucketObjects(bucketName string, prefix string) ([]string, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	defer client.Close()
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var filenames []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break // All objects have been listed.
		}
		if err != nil {
			return nil, fmt.Errorf("bucket.Objects: %w", err)
		}
		filenames = append(filenames, attrs.Name, prefix)
	}

	return filenames, nil
}

// loadOSV recursively loads all OSV vulnerabilities from a given directory path.
// It walks the directory, reads each ".json" file, and decodes it into an osvschema.Vulnerability object.
// The function returns a map of CVE IDs to their corresponding Vulnerability objects.
// Files that are not ".json" files, directories, or files ending in ".metrics.json" are skipped.
// The function will log warnings for files that fail to open or decode, and will terminate if it fails to walk the directory.
func loadOSV(osvPath string) map[cves.CVEID]osvschema.Vulnerability {
	allVulns := make(map[cves.CVEID]osvschema.Vulnerability)
	logger.Info("Loading OSV records", slog.String("path", osvPath))
	err := filepath.WalkDir(osvPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".metrics.json") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn("Failed to open OSV JSON file", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		var vuln osvschema.Vulnerability
		decodeErr := json.NewDecoder(file).Decode(&vuln)
		file.Close()
		if decodeErr != nil {
			logger.Error("Failed to decode, skipping", slog.String("file", path), slog.Any("err", decodeErr))
			return nil
		}
		allVulns[cves.CVEID(vuln.ID)] = vuln

		return nil
	})

	if err != nil {
		logger.Fatal("Failed to walk OSV directory", slog.String("path", osvPath), slog.Any("err", err))
	}

	return allVulns
}

// combineIntoOSV creates OSV entry by combining loaded CVEs from NVD and PackageInfo information from security advisories.
func combineIntoOSV(cve5osv map[cves.CVEID]osvschema.Vulnerability, nvdosv map[cves.CVEID]osvschema.Vulnerability, mandatoryCVEIDs []string) map[cves.CVEID]osvschema.Vulnerability {
	osvRecords := make(map[cves.CVEID]osvschema.Vulnerability)

	// Iterate through CVEs from security advisories (cve5) as the base
	for cveID, cve5 := range cve5osv {
		var baseOSV osvschema.Vulnerability
		nvd, ok := nvdosv[cveID]

		if ok {
			baseOSV = combineTwoOSVRecords(cve5, nvd)
			// The CVE is processed, so remove it from the nvdosv map to avoid re-processing.
			delete(nvdosv, cveID)
		} else {
			baseOSV = cve5
		}

		if len(baseOSV.Affected) == 0 {
			// check if part exists.
			if !slices.Contains(mandatoryCVEIDs, string(cveID)) {
				continue
			}
		}
		osvRecords[cveID] = baseOSV
	}

	// Add any remaining CVEs from NVD that were not in the advisory data.
	for cveID, nvd := range nvdosv {
		if len(nvd.Affected) == 0 {
			continue
		}
		osvRecords[cveID] = nvd
	}

	return osvRecords
}

// combineTwoOSVRecords takes two osv records and combines them into one
func combineTwoOSVRecords(cve5 osvschema.Vulnerability, nvd osvschema.Vulnerability) osvschema.Vulnerability {
	baseOSV := cve5
	combinedAffected := pickAffectedInformation(cve5.Affected, nvd.Affected)

	baseOSV.Affected = combinedAffected
	// Merge references, ensuring no duplicates.
	refMap := make(map[string]bool)
	for _, r := range baseOSV.References {
		refMap[r.URL] = true
	}
	for _, r := range nvd.References {
		if !refMap[r.URL] {
			baseOSV.References = append(baseOSV.References, r)
			refMap[r.URL] = true
		}
	}

	// Merge timestamps: latest modified, earliest published.
	cve5Modified := baseOSV.Modified
	if nvd.Modified.After(cve5Modified) {
		baseOSV.Modified = nvd.Modified
	}

	cve5Published := baseOSV.Published
	if nvd.Published.Before(cve5Published) {
		baseOSV.Published = nvd.Published
	}

	// Merge aliases, ensuring no duplicates.
	aliasMap := make(map[string]bool)
	for _, alias := range baseOSV.Aliases {
		aliasMap[alias] = true
	}
	for _, alias := range nvd.Aliases {
		if !aliasMap[alias] {
			baseOSV.Aliases = append(baseOSV.Aliases, alias)
			aliasMap[alias] = true
		}
	}

	return baseOSV
}

// pickAffectedInformation merges information from nvdAffected into cve5Affected.
// It matches affected packages by the repo URL in their version ranges.
// If a match is found, it merges the version range information, preferring the entry
// with more ranges. Unmatched nvdAffected packages are appended.
// It returns a new slice and does not modify cve5Affected in place.
func pickAffectedInformation(cve5Affected []osvschema.Affected, nvdAffected []osvschema.Affected) []osvschema.Affected {
	if len(nvdAffected) == 0 {
		return cve5Affected
	}
	// If NVD has more affected packages, prefer it entirely.
	if len(cve5Affected) == 0 || len(nvdAffected) > len(cve5Affected) {
		return nvdAffected
	}

	nvdRepoMap := make(map[string][]osvschema.Range)
	for _, affected := range nvdAffected {
		for _, r := range affected.Ranges {
			if r.Repo != "" {
				nvdRepoMap[r.Repo] = append(nvdRepoMap[r.Repo], r)
			}
		}
	}

	cve5RepoMap := make(map[string][]osvschema.Range)
	for _, affected := range cve5Affected {
		for _, r := range affected.Ranges {
			if r.Repo != "" {
				cve5RepoMap[r.Repo] = append(cve5RepoMap[r.Repo], r)
			}
		}
	}

	newRepoAffectedMap := make(map[string]osvschema.Affected)

	for repo, cveRanges := range cve5RepoMap {
		if nvdRanges, ok := nvdRepoMap[repo]; ok {
			var newAffectedRanges []osvschema.Range

			// Found a match. If NVD has more ranges, use its ranges.
			if len(nvdRanges) > len(cveRanges) {
				// just use  the nvd ranges
				newAffectedRanges = nvdRanges
			} else if len(nvdRanges) < len(cveRanges) {
				newAffectedRanges = cveRanges
			} else if len(cveRanges) == 1 && len(nvdRanges) == 1 {
				c5Intro, c5Fixed := getRangeBoundaryVersions(cveRanges[0].Events)
				nvdIntro, nvdFixed := getRangeBoundaryVersions(nvdRanges[0].Events)

				// Prefer cve5 data, but use nvd data if cve5 data is missing.
				if c5Intro == "" {
					c5Intro = nvdIntro
				}
				if c5Fixed == "" {
					c5Fixed = nvdFixed
				}

				if c5Intro != "" || c5Fixed != "" {
					newRange := cves.BuildVersionRange(c5Intro, "", c5Fixed)
					newRange.Repo = repo
					newRange.Type = osvschema.RangeGit // Preserve the repo
					newAffectedRanges = append(newAffectedRanges, newRange)
				}
			}
			// Remove from map so we know which NVD packages are left.
			delete(nvdRepoMap, repo)
			newRepoAffectedMap[repo] = osvschema.Affected{
				Ranges: newAffectedRanges,
			}
		} else {
			newRepoAffectedMap[repo] = osvschema.Affected{
				Ranges: cveRanges,
			}
		}
	}

	// Add remaining NVD packages that were not in cve5.
	for repo, nvdRange := range nvdRepoMap {
		newRepoAffectedMap[repo] = osvschema.Affected{
			Ranges: nvdRange,
		}
	}

	var combinedAffected []osvschema.Affected //nolint:prealloc
	for _, aff := range newRepoAffectedMap {
		combinedAffected = append(combinedAffected, aff)
	}

	return combinedAffected
}

// getRangeBoundaryVersions extracts the introduced and fixed versions from a slice of OSV events.
// It iterates through the events and returns the last non-empty "introduced" and "fixed" versions found.
func getRangeBoundaryVersions(events []osvschema.Event) (introduced, fixed string) {
	for _, e := range events {
		if e.Introduced != "0" && e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" {
			fixed = e.Fixed
		}
	}

	return introduced, fixed
}
