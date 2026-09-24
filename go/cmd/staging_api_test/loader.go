// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
)

// SimpleVuln contains essential information extracted from a vulnerability record for API querying.
type SimpleVuln struct {
	ID            string `json:"db_id"`
	Package       string `json:"package"`
	Ecosystem     string `json:"ecosystem"`
	PURL          string `json:"purl"`
	AffectedFuzzy string `json:"affected_fuzzy"`
}

// rawVulnerability is a lightweight struct for unmarshaling OSV records from JSON.
type rawVulnerability struct {
	ID       string        `json:"id"`
	Affected []rawAffected `json:"affected"`
}

type rawAffected struct {
	Package  *rawPackage `json:"package"`
	Versions []string    `json:"versions"`
	Ranges   []rawRange  `json:"ranges"`
}

type rawPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type rawRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// QueryPools holds processed vulnerabilities and partitioned query IDs for API testing.
type QueryPools struct {
	VulnMap            map[string]*SimpleVuln
	EcosystemMap       map[string][]string
	PackageMap         map[string][]string
	VulnQueryIDs       []string
	PackageQueryIDs    []string
	LargeBatchQueryIDs []string
}

// formatVuln extracts essential query fields from raw vulnerability JSON.
func formatVuln(rng *rand.Rand, raw rawVulnerability) *SimpleVuln {
	vuln := &SimpleVuln{
		ID:            raw.ID,
		Package:       "foo",
		Ecosystem:     "foo",
		PURL:          "pkg:foo/foo",
		AffectedFuzzy: "1.0.0",
	}

	if len(raw.Affected) == 0 {
		return vuln
	}

	aff := raw.Affected[rng.IntN(len(raw.Affected))]
	if aff.Package == nil {
		return vuln
	}

	if aff.Package.Name != "" {
		vuln.Package = aff.Package.Name
	}
	if aff.Package.Ecosystem != "" {
		vuln.Ecosystem = aff.Package.Ecosystem
	}
	if aff.Package.PURL != "" {
		vuln.PURL = aff.Package.PURL
	}

	var affectedFuzzy string
	if len(aff.Versions) > 0 {
		affectedFuzzy = aff.Versions[rng.IntN(len(aff.Versions))]
	}

	if affectedFuzzy == "" && len(aff.Ranges) > 0 {
		rangeItem := aff.Ranges[rng.IntN(len(aff.Ranges))]
		if len(rangeItem.Events) > 0 {
			event := rangeItem.Events[rng.IntN(len(rangeItem.Events))]
			var values []string
			for _, v := range event {
				if v != "" {
					values = append(values, v)
				}
			}
			if len(values) > 0 {
				affectedFuzzy = values[rng.IntN(len(values))]
			}
		}
	}

	if affectedFuzzy != "" {
		vuln.AffectedFuzzy = affectedFuzzy
	}

	return vuln
}

// downloadZipFromGCS downloads a zip file from GCS to a temporary local file.
func downloadZipFromGCS(ctx context.Context, client *storage.Client, bucket, objectName string) (string, error) {
	tmpFile, err := os.CreateTemp("", "all-vulns-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tmpFile.Close()

	rc, err := client.Bucket(bucket).Object(objectName).NewReader(ctx)
	if err != nil {
		_ = os.Remove(tmpFile.Name())

		return "", fmt.Errorf("failed to read %s/%s from GCS: %w", bucket, objectName, err)
	}
	defer rc.Close()

	if _, err := io.Copy(tmpFile, rc); err != nil {
		_ = os.Remove(tmpFile.Name())

		return "", fmt.Errorf("failed to download zip from GCS: %w", err)
	}

	return tmpFile.Name(), nil
}

// LoadQueryPoolsFromZip reads all vulnerability JSON files from a zip reader and constructs the query pools.
func LoadQueryPoolsFromZip(ctx context.Context, zipReader *zip.Reader, rng *rand.Rand) (*QueryPools, error) {
	vulnMap := make(map[string]*SimpleVuln)
	ecosystemMap := make(map[string][]string)
	packageMap := make(map[string][]string)

	for _, file := range zipReader.File {
		if selectErr := ctx.Err(); selectErr != nil {
			return nil, selectErr
		}
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			logger.Warn("Failed to open file in zip", "file", file.Name, "error", err)
			continue
		}

		var raw rawVulnerability
		err = json.NewDecoder(rc).Decode(&raw)
		_ = rc.Close()
		if err != nil || raw.ID == "" {
			logger.Warn("Skipping invalid JSON file in zip", "file", file.Name, "error", err)
			continue
		}

		vuln := formatVuln(rng, raw)
		vulnMap[vuln.ID] = vuln
		ecosystemMap[vuln.Ecosystem] = append(ecosystemMap[vuln.Ecosystem], vuln.ID)
		packageMap[vuln.Package] = append(packageMap[vuln.Package], vuln.ID)
	}

	vulnQueryIDs := make([]string, 0, len(vulnMap))
	for id := range vulnMap {
		vulnQueryIDs = append(vulnQueryIDs, id)
	}
	rng.Shuffle(len(vulnQueryIDs), func(i, j int) {
		vulnQueryIDs[i], vulnQueryIDs[j] = vulnQueryIDs[j], vulnQueryIDs[i]
	})

	// Make copies of package lists so we can pop from them without destroying the original packageMap
	pkgLists := make(map[string][]string, len(packageMap))
	for k, v := range packageMap {
		cp := make([]string, len(v))
		copy(cp, v)
		pkgLists[k] = cp
	}

	var packageQueryIDs []string
	for pkg, ids := range pkgLists {
		if len(ids) > 0 {
			packageQueryIDs = append(packageQueryIDs, ids[len(ids)-1])
			pkgLists[pkg] = ids[:len(ids)-1]
		}
	}
	rng.Shuffle(len(packageQueryIDs), func(i, j int) {
		packageQueryIDs[i], packageQueryIDs[j] = packageQueryIDs[j], packageQueryIDs[i]
	})

	// Get large batch query IDs (from top 5000 packages with most vulnerabilities, excluding foo and Kernel)
	type pkgCount struct {
		pkg   string
		count int
	}
	var counts []pkgCount
	for pkg, ids := range packageMap {
		if pkg == "foo" || pkg == "Kernel" {
			continue
		}
		if len(ids) > 0 {
			counts = append(counts, pkgCount{pkg: pkg, count: len(ids)})
		}
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].count > counts[j].count
	})

	const mostCommon = 5000
	limit := min(mostCommon, len(counts))

	var largeBatchQueryIDs []string
	for i := range limit {
		pkg := counts[i].pkg
		ids := pkgLists[pkg]
		if len(ids) > 0 {
			largeBatchQueryIDs = append(largeBatchQueryIDs, ids[len(ids)-1])
			pkgLists[pkg] = ids[:len(ids)-1]
		}
	}
	rng.Shuffle(len(largeBatchQueryIDs), func(i, j int) {
		largeBatchQueryIDs[i], largeBatchQueryIDs[j] = largeBatchQueryIDs[j], largeBatchQueryIDs[i]
	})

	return &QueryPools{
		VulnMap:            vulnMap,
		EcosystemMap:       ecosystemMap,
		PackageMap:         packageMap,
		VulnQueryIDs:       vulnQueryIDs,
		PackageQueryIDs:    packageQueryIDs,
		LargeBatchQueryIDs: largeBatchQueryIDs,
	}, nil
}

// LoadQueryPools downloads (if needed) and parses vulnerability records from GCS or a local zip file.
func LoadQueryPools(ctx context.Context, gcsClient *storage.Client, bucket, zipPath, localZip string, rng *rand.Rand) (*QueryPools, error) {
	zipFilePath := localZip
	isTemp := false
	if zipFilePath == "" {
		logger.Info("Downloading zip file from GCS", "bucket", bucket, "object", zipPath)
		var err error
		zipFilePath, err = downloadZipFromGCS(ctx, gcsClient, bucket, zipPath)
		if err != nil {
			return nil, err
		}
		isTemp = true
	}
	if isTemp {
		defer func() {
			//nolint:gosec // G703: Cleaning up temporary zip file
			_ = os.Remove(zipFilePath)
		}()
	}

	zipReader, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file %s: %w", filepath.Clean(zipFilePath), err)
	}
	defer zipReader.Close()

	return LoadQueryPoolsFromZip(ctx, &zipReader.Reader, rng)
}
