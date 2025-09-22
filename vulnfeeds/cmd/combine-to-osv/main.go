// package main combines CVEs and security advisories into OSV records.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/exp/slices"
	"google.golang.org/api/iterator"
)

const (
	defaultOSVOutputPath = "osv_output"
	defaultCVE5Path      = "cve5"
	defaultNVDOSVPath    = "nvd"
	defaultNVDPath       = "cve_jsons"
)

func main() {
	logger.InitGlobalLogger()

	cve5Path := flag.String("cve5Path", defaultCVE5Path, "Path to CVE file")
	nvdPath := flag.String("partsPath", defaultNVDOSVPath, "Path to CVE file")
	osvOutputPath := flag.String("osvOutputPath", defaultOSVOutputPath, "Path to CVE file")
	flag.Parse()

	err := os.MkdirAll(*osvOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	// Load CVE5 OSVs/PackageInfo
	allCVE5 := loadOSV(*cve5Path)
	// Load NVD OSVs/PackageInfo
	allNVD := loadOSV(*nvdPath)

	// nvdCVEs := vulns.LoadAllCVEs(defaultNVDOSVPath)
	debianCVEs, err := listBucketObjects("osv-test-debian-osv/debian-cve-osv")

	// Combine
	combinedData := combineIntoOSV(allCVE5, allNVD, debianCVEs)
	writeOSVFile(combinedData, *osvOutputPath)

}

// listBucketObjects lists the names of all objects in a Google Cloud Storage bucket.
// It does not download the file contents.
func listBucketObjects(bucketName string) ([]string, error) {

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	defer client.Close()

	bucket := client.Bucket(bucketName)

	it := bucket.Objects(ctx, nil)

	var filenames []string

	for {
		attrs, err := it.Next()

		if err == iterator.Done {
			break // All objects have been listed.
		}
		if err != nil {
			return nil, fmt.Errorf("bucket.Objects: %w", err)
		}

		filenames = append(filenames, attrs.Name)
	}

	return filenames, nil
}

// getModifiedTime gets the modification time of a given file
// This function assumes that the modified time on disk matches with it in GCS
func getModifiedTime(filePath string) (time.Time, error) {
	var emptyTime time.Time
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return emptyTime, err
	}
	parsedTime := fileInfo.ModTime()

	return parsedTime, err
}

func loadOSV(osvPath string) map[cves.CVEID]osvschema.Vulnerability {
	allVulns := make(map[cves.CVEID]osvschema.Vulnerability)
	dir, err := os.ReadDir(osvPath)
	if err != nil {
		logger.Fatal("Failed to read dir", slog.String("path", osvPath), slog.Any("err", err))
	}
	for _, entry := range dir {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".metrics.json") {
			continue
		}
		filePath := path.Join(osvPath, entry.Name())
		file, err := os.Open(filePath)
		if err != nil {
			logger.Fatal("Failed to open OSV JSON file", slog.String("path", filePath), slog.Any("err", err))
		}

		var vuln osvschema.Vulnerability
		err = json.NewDecoder(file).Decode(&vuln)
		file.Close()
		if err != nil {
			logger.Fatal("Failed to decode", slog.String("file", entry.Name()), slog.Any("err", err))
		}
		allVulns[cves.CVEID(vuln.ID)] = vuln
		logger.Info("Loaded "+entry.Name(), slog.String("file", entry.Name()))
	}
	return allVulns
}

// combineIntoOSV creates OSV entry by combining loaded CVEs from NVD and PackageInfo information from security advisories.
func combineIntoOSV(cve5osv map[cves.CVEID]osvschema.Vulnerability, nvdosv map[cves.CVEID]osvschema.Vulnerability, debianCVEs []string) map[cves.CVEID]osvschema.Vulnerability {
	vulns := make(map[cves.CVEID]osvschema.Vulnerability)

	// Iterate through CVEs from security advisories (cve5) as the base
	for cveID, cve5 := range cve5osv {
		combined := cve5 // Start with the cve5 record
		nvd, ok := nvdosv[cveID]

		if ok {
			// If the cve5-derived record has no affected packages, use NVD's.
			if len(combined.Affected) == 0 && len(nvd.Affected) > 0 {
				combined.Affected = nvd.Affected
			}

			// TODO: if both NVD and CVE5 data exists, compare each affected range and make good decisions

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
			if !slices.Contains(debianCVEs, string(cveID)) {
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
