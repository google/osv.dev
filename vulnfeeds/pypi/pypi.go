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
	"sort"
	"strings"

	"github.com/aquasecurity/go-pep440-version"

	"github.com/google/osv/vulnfeeds/cves"
)

type pypiLinks struct {
	Name  string   `json:"name"`
	Links []string `json:"links"`
}

type pypiVersions struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type PyPI struct {
	links           map[string][]string
	versions        map[string][]string
	checkedPackages map[string]bool
}

const (
	pypiSimple = "https://pypi.org/simple/"
)

// linkBlocklist is a set of reference links to reject.
var linkBlocklist = map[string]bool{
	"https://github.com":         true,
	"https://gitlab.com":         true,
	"https://bitbucket.com":      true,
	"https://pypi.org":           true,
	"https://jira.atlassian.com": true,
}

func readOrPanic(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", path, err)
	}

	return data
}

func loadLinks(path string) []pypiLinks {
	data := readOrPanic(path)

	var links []pypiLinks
	err := json.Unmarshal(data, &links)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", err)
	}
	return links
}

func loadVersions(path string) []pypiVersions {
	data := readOrPanic(path)

	var versions []pypiVersions
	err := json.Unmarshal(data, &versions)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", err)
	}
	return versions
}

// processLinks takes a pypi_links.json and returns a map of links to list of packages.
func processLinks(linksSource []pypiLinks) map[string][]string {
	links := map[string]map[string]bool{}
	for _, pkg := range linksSource {
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

	// Sort package names by longest length first to prioritise packages with longer names.
	processedLinks := map[string][]string{}
	for link, pkgs := range links {
		processedLinks[link] = make([]string, 0, len(pkgs))
		for pkg := range pkgs {
			processedLinks[link] = append(processedLinks[link], pkg)
		}

		sortedPkgs := processedLinks[link]
		sort.Slice(processedLinks[link], func(i, j int) bool {
			return len(sortedPkgs[i]) > len(sortedPkgs[j])
		})
	}
	return processedLinks
}

// processVersions takes a pypi_versions.json and returns a map of packages to versions.
func processVersions(versionsSource []pypiVersions) map[string][]string {
	versions := map[string][]string{}
	for _, data := range versionsSource {
		versions[data.Name] = data.Versions
	}
	return versions
}

func New(pypiLinksPath string, pypiVersionsPath string) *PyPI {
	linksSource := loadLinks(pypiLinksPath)
	versionsSource := loadVersions(pypiVersionsPath)

	return &PyPI{
		links:           processLinks(linksSource),
		versions:        processVersions(versionsSource),
		checkedPackages: map[string]bool{},
	}
}

func (p *PyPI) Matches(cve cves.CVEItem) string {
	desc := cves.EnglishDescription(cve.CVE)
	for _, reference := range cve.CVE.References.ReferenceData {
		if pkg := extractPyPIProject(reference.URL); pkg != "" {
			log.Printf("Matched via PyPI link: %s", reference.URL)
			return pkg
		}

		if pkg := p.matchesPackage(reference.URL, desc); pkg != "" {
			return pkg
		}
	}
	return ""
}

func (p *PyPI) Versions(pkg string) []string {
	versions := p.versions[pkg]
	if versions == nil {
		return nil
	}

	sort.Slice(versions, func(i, j int) bool {
		versionI, err := version.Parse(versions[i])
		if err != nil {
			log.Panicf("Failed to parse version %s: %v", versions[i], err)
		}

		versionJ, err := version.Parse(versions[j])
		if err != nil {
			log.Panicf("Failed to parse version %s: %v", versions[j], err)
		}

		return versionI.LessThan(versionJ)
	})
	return versions
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
		for _, pkg := range pkgs {
			log.Printf("Got potential match for %s: %s", link, pkg)
			// If we get a match, make sure the vulnerability description
			// mentions our package name as an additional check to avoid
			// false positives.
			if strings.Contains(strings.ToLower(desc), strings.ToLower(pkg)) && p.packageExists(pkg) {
				log.Printf("Matched description")
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
