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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/pypi"
	"github.com/google/osv/vulnfeeds/vulns"
)

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON.")
	pypiJson := flag.String("pypi_json", "", "Path to pypi.json.")
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

	ecosystem := pypi.NewPyPI(*pypiJson)
	for _, cve := range parsed.CVEItems {
		pkg := ""
		if pkg = ecosystem.Matches(cve); pkg == "" {
			continue
		}

		v := vulns.FromCVE(cve, pkg, "PyPI", "ECOSYSTEM")
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
		err = ioutil.WriteFile(vulnPath, data, 0644)
		if err != nil {
			log.Fatalf("Failed to write %s: %v", vulnPath, err)
		}
	}
}
