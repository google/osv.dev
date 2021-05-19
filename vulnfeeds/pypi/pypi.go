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
	"regexp"
	"sort"
	"strings"

	"github.com/aquasecurity/go-pep440-version"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/triage"
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
	// links is a map of link -> array of packages with that link referenced somewhere on PyPI.
	links map[string][]string
	// versions is a map of package name -> array of versions.
	versions map[string][]string
	// vendorProductToPkg is a map of "vendor/product" to package names.
	vendorProductToPkg map[string][]string
	// checkedPackages is a cache that stores whether a package still exists on PyPI.
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
	"https://bitbucket.org":      true,
	"https://twitter.com":        true,
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

// NormalizePackageName normalizes a PyPI package name.
func NormalizePackageName(name string) string {
	// Per https://www.python.org/dev/peps/pep-0503/#normalized-names
	re := regexp.MustCompile(`[-_.]+`)
	return strings.ToLower(re.ReplaceAllString(name, "-"))
}

// extractVendorProduct takes a link and extracts the "vendor/product" from it
// if the link is a VCS link.
func extractVendorProduct(link string) string {
	// Example: https://github.com/vendor/product
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}

	if u.Host != "github.com" && u.Host != "bitbucket.org" && u.Host != "gitlab.com" {
		return ""
	}

	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 {
		return ""
	}

	return strings.ToLower(parts[1]) + "/" + strings.ToLower(parts[2])
}

// processLinks takes a pypi_links.json and returns a map of links to list of
// packages and a map of "vendor/product" to packages.
func processLinks(linksSource []pypiLinks) (map[string][]string, map[string][]string) {
	vendorProductToPkg := map[string][]string{}
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

			if vendorProduct := extractVendorProduct(link); vendorProduct != "" {
				vendorProductToPkg[vendorProduct] = append(vendorProductToPkg[vendorProduct], pkg.Name)
			}
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

	return processedLinks, vendorProductToPkg
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

	links, vendorProductToPkg := processLinks(linksSource)
	return &PyPI{
		links:              links,
		versions:           processVersions(versionsSource),
		checkedPackages:    map[string]bool{},
		vendorProductToPkg: vendorProductToPkg,
	}
}

func (p *PyPI) Matches(cve cves.CVEItem, falsePositives *triage.FalsePositives) string {
	for _, reference := range cve.CVE.References.ReferenceData {
		// If there is a PyPI link, it must be a Python package. These take precedence.
		if pkg := extractPyPIProject(reference.URL); pkg != "" {
			log.Printf("Matched via PyPI link: %s", reference.URL)
			return pkg
		}
	}

	for _, reference := range cve.CVE.References.ReferenceData {
		// Otherwise try to cross-reference the link against our set of known links.
		if pkg := p.matchesPackage(reference.URL, cve.CVE, falsePositives); pkg != "" {
			return pkg
		}
	}

	// As a last resort, extract the vendor and product from the CPE and try to match that
	// against vendor/product combinations extracted from e.g. GitHub links.
	cpes := cves.CPEs(cve)
	if len(cpes) == 0 {
		return ""
	}

	cpe := strings.Split(cpes[0], ":")
	if len(cpe) < 5 {
		return ""
	}

	vendorProduct := cpe[3] + "/" + cpe[4]
	if pkgs, exists := p.vendorProductToPkg[vendorProduct]; exists {
		for _, pkg := range pkgs {
			if p.finalPkgCheck(cve.CVE, pkg, falsePositives) {
				return pkg
			}
		}
	}
	return ""
}

func filterVersions(versions []string) []string {
	var filtered []string
	for _, v := range versions {
		if _, err := version.Parse(v); err == nil {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func (p *PyPI) Versions(pkg string) []string {
	versions := filterVersions(p.versions[pkg])
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

func (p *PyPI) finalPkgCheck(cve cves.CVE, pkg string, falsePositives *triage.FalsePositives) bool {
	// To avoid false positives, check that the pkg name is mentioned in the description.
	desc := strings.ToLower(cves.EnglishDescription(cve))
	pkgNameParts := strings.Split(pkg, "-")

	for _, part := range pkgNameParts {
		// Python packages can commonly be py<name> or <name>-py.
		// Remove this to be a bit more lenient when matching against the description.
		part = strings.TrimPrefix(part, "py")
		part = strings.TrimSuffix(part, "py")
		if !strings.Contains(desc, strings.ToLower(part)) {
			return false
		}
	}
	log.Printf("Matched description")

	if falsePositives.CheckPackage(pkg) && !strings.Contains(desc, "python") {
		// If this package is listed as a false positive, and the description does not
		// mention "python" anywhere, it's most likely a true false positive.
		return false
	}

	// Finally check that the package still exists.
	return p.packageExists(pkg)
}

// matchesPackage checks if a given reference link matches a PyPI package.
func (p *PyPI) matchesPackage(link string, cve cves.CVE, falsePositives *triage.FalsePositives) string {
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
			if p.finalPkgCheck(cve, pkg, falsePositives) {
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

	// Should be /project/<name>
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || parts[1] != "project" {
		return ""
	}

	return parts[2]
}
