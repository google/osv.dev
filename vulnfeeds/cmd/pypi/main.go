// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package main contains a utility to generate PyPI OSV records.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/osv/vulnfeeds/models"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/pypi"
	"github.com/google/osv/vulnfeeds/triage"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	extension = ".yaml"
)

func loadExisting(vulnsDir string) (map[string]bool, error) {
	ids := map[string]bool{}
	err := filepath.Walk(vulnsDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to access %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, extension) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", path, err)
		}
		defer f.Close()

		vuln, err := vulns.FromYAML(f)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		ids[vuln.GetId()+"/"+vuln.GetAffected()[0].GetPackage().GetName()] = true
		for _, alias := range vuln.GetAliases() {
			ids[alias+"/"+vuln.GetAffected()[0].GetPackage().GetName()] = true
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk: %w", err)
	}

	return ids, nil
}

func anyUnbounded(v *vulns.Vulnerability) bool {
	for _, affected := range v.Affected {
		for _, ranges := range affected.GetRanges() {
			hasFixed := false
			hasLastAffected := false
			for _, event := range ranges.GetEvents() {
				if event.GetFixed() != "" {
					hasFixed = true
				}
				if event.GetLastAffected() != "" {
					hasLastAffected = true
				}
			}
			if !hasFixed && !hasLastAffected {
				return true
			}
		}
	}

	return false
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON.")
	pypiLinksPath := flag.String("pypi_links", "", "Path to pypi_links.json.")
	pypiVersionsPath := flag.String("pypi_versions", "", "Path to pypi_versions.json.")
	falsePositivesPath := flag.String("false_positives", "", "Path to false positives file.")
	withoutNotes := flag.Bool("without_notes", false, "Output vulnerabilities without notes only.")
	excludeUnbounded := flag.Bool("exclude_unbounded", false, "Exclude vulnerabilities with unbounded affected ranges.")
	outDir := flag.String("out_dir", "", "Path to output results.")

	flag.Parse()

	logger.InitGlobalLogger()

	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		logger.Fatal("Failed to open file", slog.Any("err", err))
	}
	var parsed models.CVEAPIJSON20Schema
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		logger.Fatal("Failed to parse NVD CVE JSON", slog.Any("err", err))
	}

	falsePositives, err := triage.LoadFalsePositives(*falsePositivesPath)
	if err != nil {
		logger.Fatal("Failed to load false positives file", slog.String("path", *falsePositivesPath), slog.Any("err", err))
	}

	ecosystem := pypi.New(*pypiLinksPath, *pypiVersionsPath)
	existingIDs, err := loadExisting(*outDir)
	if err != nil {
		logger.Fatal("Failed to load existing IDs", slog.Any("err", err))
	}

	for _, cve := range parsed.Vulnerabilities {
		if falsePositives.CheckID(string(cve.CVE.ID)) {
			logger.Info("Skipping as a false positive", slog.String("cve", string(cve.CVE.ID)))
			continue
		}

		pkgs := ecosystem.Matches(cve.CVE, falsePositives)
		if len(pkgs) == 0 {
			continue
		}

		for _, pkg := range pkgs {
			if _, exists := existingIDs[string(cve.CVE.ID)+"/"+pkg]; exists {
				logger.Info("Skipping match as it already exists", slog.String("cve", string(cve.CVE.ID)), slog.String("package", pkg))
				continue
			}

			logger.Info("Matched CVE to package", slog.String("cve", string(cve.CVE.ID)), slog.String("package", pkg))
			validVersions := ecosystem.Versions(pkg)
			if validVersions == nil {
				logger.Info("Package does not have valid versions, skipping", slog.String("package", pkg))
				continue
			}
			logger.Info("Got valid versions", slog.Any("versions", validVersions))

			id := "PYSEC-0000-" + cve.CVE.ID // To be assigned later.
			purl := ecosystem.PackageURL(pkg)
			pkgInfo := vulns.PackageInfo{
				PkgName:   pkg,
				Ecosystem: "PyPI",
				PURL:      purl,
			}

			v := vulns.FromNVDCVE(id, cve.CVE)
			v.AddPkgInfo(pkgInfo)
			versions, notes := cves.ExtractVersionInfo(cve.CVE, validVersions, http.DefaultClient)

			vulns.AttachExtractedVersionInfo(v, versions)
			if len(v.Affected[0].GetRanges()) == 0 {
				logger.Info("No affected versions detected")
			}

			if *excludeUnbounded && anyUnbounded(v) {
				logger.Info("Skipping as we could not find an upperbound version", slog.String("cve", string(cve.CVE.ID)))
				continue
			}

			pkgDir := filepath.Join(*outDir, pkg)
			err = os.MkdirAll(pkgDir, 0755)
			if err != nil {
				logger.Fatal("Failed to create dir", slog.Any("err", err))
			}

			vulnPath := filepath.Join(pkgDir, v.Id+extension)
			if _, err := os.Stat(vulnPath); err == nil {
				logger.Info("Skipping as it already exists", slog.String("path", vulnPath))
				continue
			}

			if len(notes) > 0 && *withoutNotes {
				logger.Info("Skipping as there are notes associated with it", slog.String("path", vulnPath))
				continue
			}

			f, err := os.Create(vulnPath)
			if err != nil {
				logger.Fatal("Failed to open for writing", slog.String("path", vulnPath), slog.Any("err", err))
			}
			defer f.Close()
			err = v.ToYAML(f)
			if err != nil {
				logger.Panic("Failed to write", slog.String("path", vulnPath), slog.Any("err", err))
			}

			// If there are notes that require human intervention, write them to the end of the YAML.
			if len(notes) > 0 {
				notesPath := filepath.Join(pkgDir, v.Id+".notes")
				_, err = f.WriteString("\n# <Vulnfeeds Notes>\n# " + strings.Join(notes, "\n# "))
				if err != nil {
					logger.Panic("Failed to write", slog.String("path", notesPath), slog.Any("err", err))
				}
			}
		}
	}
}
