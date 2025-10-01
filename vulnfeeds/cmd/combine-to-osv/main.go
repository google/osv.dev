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
	"path"
	"path/filepath"
	"strings"

	"slices"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/iterator"
)

const (
	defaultOSVOutputPath = "osv_output"
	defaultCVE5Path      = "cve5"
	defaultNVDOSVPath    = "nvd"
)

func main() {
	logger.InitGlobalLogger()

	cve5Path := flag.String("cve5Path", defaultCVE5Path, "Path to CVE file")
	nvdPath := flag.String("nvdPath", defaultNVDOSVPath, "Path to CVE file")
	osvOutputPath := flag.String("osvOutputPath", defaultOSVOutputPath, "Path to CVE file")
	flag.Parse()

	err := os.MkdirAll(*osvOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	// Load CVE5 OSVs
	allCVE5 := loadOSV(*cve5Path)
	// Load NVD OSVs
	allNVD := loadOSV(*nvdPath)

	// nvdCVEs := vulns.LoadAllCVEs(defaultNVDOSVPath)
	debianCVEs, err := listBucketObjects("osv-test-debian-osv", "/debian-cve-osv")
	if err != nil {
		logger.Warn("Failed to list debian cves", slog.Any("err", err))
	}
	alpineCVEs, err := listBucketObjects("osv-test-cve-osv-conversion", "/alpine")
	if err != nil {
		logger.Warn("Failed to list alpine cves", slog.Any("err", err))
	}

	noPkg := append(debianCVEs, alpineCVEs...) //nolint:gocritic
	// Combine
	combinedData := combineIntoOSV(allCVE5, allNVD, noPkg)
	writeOSVFile(combinedData, *osvOutputPath)
}

func cleanFilename(filename string, prefix string) string {
	cleaned := strings.TrimPrefix(filename, prefix)
	cleaned = strings.TrimSuffix(cleaned, ".json")
	pre := strings.SplitAfter(cleaned, "-")
	if pre[0] != "CVE" {
		cleaned = pre[1]
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

		filenames = append(filenames, cleanFilename(attrs.Name, prefix))
	}

	return filenames, nil
}

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
func combineIntoOSV(cve5osv map[cves.CVEID]osvschema.Vulnerability, nvdosv map[cves.CVEID]osvschema.Vulnerability, noPkgCVEs []string) map[cves.CVEID]osvschema.Vulnerability {
	vulns := make(map[cves.CVEID]osvschema.Vulnerability)

	// Iterate through CVEs from security advisories (cve5) as the base
	for cveID, cve5 := range cve5osv {
		combined := cve5 // Start with the cve5 record
		nvd, ok := nvdosv[cveID]

		if ok {
			pickAffectedInformation(&combined.Affected, nvd.Affected)

			// Merge references, ensuring no duplicates.
			refMap := make(map[string]bool)
			for _, r := range combined.References {
				refMap[r.URL] = true
			}
			for _, r := range nvd.References {
				if !refMap[r.URL] {
					combined.References = append(combined.References, r)
					refMap[r.URL] = true
				}
			}

			// Merge timestamps: latest modified, earliest published.
			cve5Modified := combined.Modified
			if nvd.Modified.After(cve5Modified) {
				combined.Modified = nvd.Modified
			}

			cve5Published := combined.Published
			if nvd.Published.Before(cve5Published) {
				combined.Published = nvd.Published
			}

			// Merge aliases, ensuring no duplicates.
			aliasMap := make(map[string]bool)
			for _, alias := range combined.Aliases {
				aliasMap[alias] = true
			}
			for _, alias := range nvd.Aliases {
				if !aliasMap[alias] {
					combined.Aliases = append(combined.Aliases, alias)
					aliasMap[alias] = true
				}
			}

			// TODO: Elegantly handle combining severity scores

			// The CVE is processed, so remove it from the nvdosv map to avoid re-processing.
			delete(nvdosv, cveID)
		}
		if len(combined.Affected) == 0 {
			// check if part exists.
			if !slices.Contains(noPkgCVEs, string(cveID)) {
				// logger.Info("No affected range, so skipping.")
				continue
			}
		}
		vulns[cveID] = combined
	}

	// Add any remaining CVEs from NVD that were not in the advisory data.
	for cveID, nvd := range nvdosv {
		vulns[cveID] = nvd
		logger.Info("" + string(cveID))
	}

	return vulns
}

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

// pickAffectedInformation merges information from nvdAffected into cve5Affected.
// It matches affected packages by the repo URL in their version ranges.
// If a match is found, it merges the version range information, preferring the entry
// with more ranges. Unmatched nvdAffected packages are appended.
// cve5Affected is modified in place.
func pickAffectedInformation(cve5Affected *[]osvschema.Affected, nvdAffected []osvschema.Affected) {
	if len(nvdAffected) == 0 {
		return
	}
	// If NVD has more affected packages, prefer it entirely.
	// cve5 := *cve5Affected
	if len(*cve5Affected) == 0 || len(nvdAffected) > len(*cve5Affected) {
		*cve5Affected = nvdAffected
		return
	}

	nvdRepoMap := make(map[string][]osvschema.Range)
	for _, affected := range nvdAffected {
		// Assuming one range per affected for matching purposes.
		if len(affected.Ranges) > 0 && affected.Ranges[0].Repo != "" {
			for _, r := range affected.Ranges {
				x, ok := nvdRepoMap[r.Repo]
				if ok {
					nvdRepoMap[r.Repo] = append(x, r)
				} else {
					nvdRepoMap[r.Repo] = append([]osvschema.Range{}, r)
				}
			}
		}
	}

	cve5RepoMap := make(map[string][]osvschema.Range)
	for _, affected := range *cve5Affected {
		// Assuming one range per affected for matching purposes.
		if len(affected.Ranges) > 0 && affected.Ranges[0].Repo != "" {
			for _, r := range affected.Ranges {
				x, ok := cve5RepoMap[r.Repo]
				if ok {
					cve5RepoMap[r.Repo] = append(x, r)
				} else {
					cve5RepoMap[r.Repo] = append([]osvschema.Range{}, r)
				}
			}
		}
	}

	newAffectedMap := make(map[string]osvschema.Affected)

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
				finalIntro := c5Intro
				if finalIntro == "" {
					finalIntro = nvdIntro
				}

				finalFixed := c5Fixed
				if finalFixed == "" {
					finalFixed = nvdFixed
				}

				if finalIntro != "" || finalFixed != "" {
					newRange := cves.BuildVersionRange(finalIntro, "", finalFixed)
					newRange.Repo = repo
					newRange.Type = osvschema.RangeGit // Preserve the repo
					newAffectedRanges = append(newAffectedRanges, newRange)
				}
			}
			// Remove from map so we know which NVD packages are left.
			delete(nvdRepoMap, repo)
			delete(cve5RepoMap, repo)
			newAffectedMap[repo] = osvschema.Affected{
				Ranges: newAffectedRanges,
			}
		}
	}

	// Add remaining NVD packages that were not in cve5.
	for repo, nvdRange := range nvdRepoMap {
		newAffectedMap[repo] = osvschema.Affected{
			Ranges: nvdRange,
		}
	}

	newAffected := make([]osvschema.Affected, 0, len(newAffectedMap))
	for _, aff := range newAffectedMap {
		newAffected = append(newAffected, aff)
	}

	*cve5Affected = newAffected
}

// writeOSVFile writes out the given osv objects into individual json files
func writeOSVFile(osvData map[cves.CVEID]osvschema.Vulnerability, osvOutputPath string) {
	for vID, osv := range osvData {
		filePath := path.Join(osvOutputPath, string(vID)+".json")
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			logger.Fatal("Failed to create/open file to write", slog.Any("err", err))
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(osv)
		if err != nil {
			file.Close()
			logger.Fatal("Failed to encode OSVs", slog.Any("err", err))
		}
		file.Close()
	}

	logger.Info("Successfully written OSV files", slog.Int("count", len(osvData)))
}
