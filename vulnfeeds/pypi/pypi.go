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

package pypi

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
)

type pypiExport struct {
	Links []string `json:"links"`
	Name  string   `json:"name"`
}

type PyPI struct {
	links           map[string]map[string]bool
	checkedPackages map[string]bool
}

const (
	pypiSimple = "https://pypi.org/simple/"
)

// linkBlocklist is a set of reference links to reject.
var linkBlocklist = map[string]bool{
	"https://github.com": true,
}

func NewPyPI(pypiJSON string) *PyPI {
	data, err := ioutil.ReadFile(pypiJSON)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", pypiJSON, err)
	}

	var pypiData []pypiExport
	err = json.Unmarshal(data, &pypiData)
	if err != nil {
		log.Fatalf("Failed to parse pypi.json: %v", err)
	}

	links := map[string]map[string]bool{}
	for _, pkg := range pypiData {
		for _, link := range pkg.Links {
			link = strings.TrimRight(link, "/")
			if _, exists := linkBlocklist[link]; exists {
				continue
			}

			if _, exists := links[link]; !exists {
				links[link] = make(map[string]bool)
			}
			links[link][pkg.Name] = true
		}
	}

	return &PyPI{links: links, checkedPackages: map[string]bool{}}
}

func (p *PyPI) Matches(cve cves.CVEItem) string {
	desc := cves.EnglishDescription(cve.CVE)
	for _, reference := range cve.CVE.References.ReferenceData {
		if pkg := extractPyPIProject(reference.URL); pkg != "" {
			return pkg
		}

		if pkg := p.matchesPackage(reference.URL, desc); pkg != "" {
			return pkg
		}
	}
	return ""
}

func (p *PyPI) packageExists(pkg string) bool {
	if result, exists := p.checkedPackages[pkg]; exists {
		return result
	}

	resp, err := http.Get(pypiSimple + pkg + "/")
	if err != nil {
		log.Panicf("Failed to call create request: %v", err)
	}

	result := resp.StatusCode == http.StatusOK
	p.checkedPackages[pkg] = result
	return result
}

// matchesPackage checks if a given reference link matches a PyPI package.
func (p *PyPI) matchesPackage(link string, desc string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}

	// Repeatedly strip the last component in the URL.
	pathParts := strings.Split(u.Path, "/")
	for i := len(pathParts); i > 0; i-- {
		u.Path = strings.Join(pathParts[0:i], "/")
		fullURL := u.String()

		pkgs, exists := p.links[fullURL]
		if !exists {
			pkgs, exists = p.links[fullURL+"/"]
		}
		if !exists {
			continue
		}

		// Check that the package still exists on PyPI.
		for pkg := range pkgs {
			if !p.packageExists(pkg) {
				continue
			}
			// If we get a match, make sure the vulnerability description
			// mentions our package name as an additional check to avoid
			// false positives.
			if strings.Contains(strings.ToLower(desc), strings.ToLower(pkg)) {
				return pkg
			}
		}
	}
	return ""
}

func extractPyPIProject(link string) string {
	// Example: https://pypi.org/project/tensorflow
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}

	if u.Host != "pypi.org" {
		return ""
	}

	// Should be project/<name>
	parts := strings.Split(u.Path, "/")
	if len(parts) < 2 || parts[0] != "project" {
		return ""
	}

	return parts[1]
}
