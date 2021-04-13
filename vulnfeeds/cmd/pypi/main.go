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
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/pypi"
	"github.com/google/osv/vulnfeeds/vulns"
)

func loadFalsePositives(path string) map[string]bool {
	falsePositives := map[string]bool{}

	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return falsePositives
	}
	if err != nil {
		log.Fatalf("Failed to open %s: %v", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		falsePositives[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Failed to read lines: %v", err)
	}

	return falsePositives
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON.")
	pypiLinksPath := flag.String("pypi_links", "", "Path to pypi_links.json.")
	pypiVersionsPath := flag.String("pypi_versions", "", "Path to pypi_versions.json.")
	falsePositivesPath := flag.String("false_positives", "", "Path to false positives file.")
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

	falsePositives := loadFalsePositives(*falsePositivesPath)
	ecosystem := pypi.New(*pypiLinksPath, *pypiVersionsPath)
	for _, cve := range parsed.CVEItems {
		if _, exists := falsePositives[cve.CVE.CVEDataMeta.ID]; exists {
			log.Printf("Skipping %s as a false positive.", cve.CVE.CVEDataMeta.ID)
			continue
		}

		pkg := ""
		if pkg = ecosystem.Matches(cve); pkg == "" {
			continue
		}

		log.Printf("Matched %s to %s.", cve.CVE.CVEDataMeta.ID, pkg)
		validVersions := ecosystem.Versions(pkg)
		if validVersions == nil {
			log.Printf("pkg %s does not have valid versions, skipping", pkg)
			continue
		}
		log.Printf("Valid versions = %v\n", validVersions)

		v, notes := vulns.FromCVE(cve, pkg, "PyPI", "ECOSYSTEM", validVersions)
		if len(v.Affects.Ranges) == 0 {
			log.Printf("No affected versions detected.")
		}

		data, err := yaml.Marshal(v)
		if err != nil {
			log.Fatalf("Failed to marshal YAML: %v", err)
		}

		pkgDir := filepath.Join(*outDir, pkg)
		err = os.MkdirAll(pkgDir, 0755)
		if err != nil {
			log.Fatalf("Failed to create dir: %v", err)
		}

		vulnPath := filepath.Join(pkgDir, v.ID+".yaml")
		if _, err := os.Stat(vulnPath); err == nil {
			log.Printf("Skipping %s as it already exists.", vulnPath)
			continue
		}

		err = ioutil.WriteFile(vulnPath, data, 0644)
		if err != nil {
			log.Fatalf("Failed to write %s: %v", vulnPath, err)
		}

		// If there are notes that require human intervention, write them.
		if len(notes) > 0 {
			notesPath := filepath.Join(pkgDir, v.ID+".notes")
			err = ioutil.WriteFile(notesPath, []byte(strings.Join(notes, "\n")), 0644)
			if err != nil {
				log.Fatalf("Failed to write %s: %v", notesPath, err)
			}
		}
	}
}
