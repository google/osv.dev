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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/pypi"
	"github.com/google/osv/vulnfeeds/triage"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	extension = ".yaml"
)

func loadExisting(vulnsDir string) (map[string]bool, error) {
	ids := map[string]bool{}
	err := filepath.Walk(vulnsDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("Failed to access %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, extension) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("Failed to open %s: %w", path, err)
		}
		defer f.Close()

		vuln, err := vulns.FromYAML(f)
		if err != nil {
			return fmt.Errorf("Failed to parse %s: %w", path, err)
		}

		ids[vuln.ID+"/"+vuln.Affected[0].Package.Name] = true
		for _, alias := range vuln.Aliases {
			ids[alias+"/"+vuln.Affected[0].Package.Name] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to walk: %w", err)
	}

	return ids, nil
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON.")
	pypiLinksPath := flag.String("pypi_links", "", "Path to pypi_links.json.")
	pypiVersionsPath := flag.String("pypi_versions", "", "Path to pypi_versions.json.")
	falsePositivesPath := flag.String("false_positives", "", "Path to false positives file.")
	withoutNotes := flag.Bool("without_notes", false, "Output vulnerabilities without notes only.")
	outDir := flag.String("out_dir", "", "Path to output results.")

	flag.Parse()

	data, err := ioutil.ReadFile(*jsonPath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	var parsed cves.NVDCVE
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		log.Fatalf("Failed to parse NVD CVE JSON: %v", err)
	}

	falsePositives, err := triage.LoadFalsePositives(*falsePositivesPath)
	if err != nil {
		log.Fatalf("Failed to load false positives file %s: %v", *falsePositivesPath, err)
	}

	ecosystem := pypi.New(*pypiLinksPath, *pypiVersionsPath)
	existingIDs, err := loadExisting(*outDir)
	if err != nil {
		log.Fatalf("Failed to load existing IDs: %v", err)
	}

	for _, cve := range parsed.CVEItems {
		if falsePositives.CheckID(cve.CVE.CVEDataMeta.ID) {
			log.Printf("Skipping %s as a false positive.", cve.CVE.CVEDataMeta.ID)
			continue
		}

		pkgs := ecosystem.Matches(cve, falsePositives)
		if len(pkgs) == 0 {
			continue
		}

		for _, pkg := range pkgs {
			if _, exists := existingIDs[cve.CVE.CVEDataMeta.ID+"/"+pkg]; exists {
				log.Printf("Skipping %s match for %s as it already exists.", cve.CVE.CVEDataMeta.ID, pkg)
				continue
			}

			log.Printf("Matched %s to %s.", cve.CVE.CVEDataMeta.ID, pkg)
			validVersions := ecosystem.Versions(pkg)
			if validVersions == nil {
				log.Printf("pkg %s does not have valid versions, skipping", pkg)
				continue
			}
			log.Printf("Valid versions = %v\n", validVersions)

			id := "PYSEC-0000-" + cve.CVE.CVEDataMeta.ID // To be assigned later.
			purl := ecosystem.PackageURL(pkg)
			pkgInfo := vulns.PackageInfo{
				PkgName:   pkg,
				Ecosystem: "PyPI",
				PURL:      purl,
			}

			v, notes := vulns.FromCVE(id, cve)
			v.AddPkgInfo(pkgInfo)
			versions, versionNotes := cves.ExtractVersionInfo(cve, validVersions)
			notes = append(notes, versionNotes...)
			v.Affected[0].AttachExtractedVersionInfo(versions)
			if len(v.Affected[0].Ranges) == 0 {
				log.Printf("No affected versions detected.")
			}

			pkgDir := filepath.Join(*outDir, pkg)
			err = os.MkdirAll(pkgDir, 0755)
			if err != nil {
				log.Fatalf("Failed to create dir: %v", err)
			}

			vulnPath := filepath.Join(pkgDir, v.ID+extension)
			if _, err := os.Stat(vulnPath); err == nil {
				log.Printf("Skipping %s as it already exists.", vulnPath)
				continue
			}

			if len(notes) > 0 && *withoutNotes {
				log.Printf("Skipping %s as there are notes associated with it.", vulnPath)
				continue
			}

			f, err := os.Create(vulnPath)
			if err != nil {
				log.Fatalf("Failed to open %s for writing: %v", vulnPath, err)
			}
			defer f.Close()
			err = v.ToYAML(f)
			if err != nil {
				log.Fatalf("Failed to write %s: %v", vulnPath, err)
			}

			// If there are notes that require human intervention, write them to the end of the YAML.
			if len(notes) > 0 {
				notesPath := filepath.Join(pkgDir, v.ID+".notes")
				_, err = f.WriteString("\n# <Vulnfeeds Notes>\n# " + strings.Join(notes, "\n# "))
				if err != nil {
					log.Fatalf("Failed to write %s: %v", notesPath, err)
				}
			}
		}
	}
}
