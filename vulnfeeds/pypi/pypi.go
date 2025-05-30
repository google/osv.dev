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

	version "github.com/aquasecurity/go-pep440-version"

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
	"https://pypi.org/project":   true,
	"https://jira.atlassian.com": true,
	"https://www.python.org":     true,
	"https://gitee.com":          true,
	"http://github.com":          true,
	"http://www.cisco.com":       true,
	"http://www.redhat.com":      true,
	"http://www.hp.com":          true,
	"http://www.oracle.com":      true,
	"https://www.oracle.com":     true,
	"http://www.python.org":      true,
	"http://dev.mysql.com":       true,
	"https://aws.amazon.com":     true,
	"https://github.com/aws":     true,
	"unknown":                    true,
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
		log.Fatalf("Failed to parse %s: %v", data, err)
	}
	return links
}

func loadVersions(path string) []pypiVersions {
	data := readOrPanic(path)

	var versions []pypiVersions
	err := json.Unmarshal(data, &versions)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", data, err)
	}
	return versions
}

// NormalizePackageName normalizes a PyPI package name.
func NormalizePackageName(name string) string {
	// Per https://www.python.org/dev/peps/pep-0503/#normalized-names
	re := regexp.MustCompile(`[-_.]+`)
	return strings.ToLower(re.ReplaceAllString(name, "-"))
}

func hasPrefix(list []string, item string) bool {
	for _, candidate := range list {
		if item == candidate {
			// Don't count exact matches.
			continue
		}

		if strings.HasPrefix(candidate, item) {
			return true
		}
	}
	return false
}

func processMatches(names []string) []string {
	// Normalize all PyPI package names.
	normalized := make([]string, 0, len(names))
	encountered := map[string]bool{}
	for _, name := range names {
		normalizedName := NormalizePackageName(name)

		if _, exists := encountered[normalizedName]; !exists {
			encountered[normalizedName] = true
			normalized = append(normalized, normalizedName)
		}
	}

	// Then filter out package names which are a prefix of another.
	// It's very likely it's a false positive and we should take the longest match.
	filtered := make([]string, 0, len(names))
	for _, name := range normalized {
		if !hasPrefix(normalized, name) {
			filtered = append(filtered, name)
		}
	}
	return filtered
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

	return strings.ToLower(parts[1]) + "/" + strings.TrimSuffix(strings.ToLower(parts[2]), ".git")
}

// processLinks takes a pypi_links.json and returns a map of links to list of
// packages and a map of "vendor/product" to packages.
func processLinks(linksSource []pypiLinks) (map[string][]string, map[string][]string) {
	vendorProductToPkg := map[string][]string{}
	links := map[string]map[string]bool{}
	for _, pkg := range linksSource {
		for _, link := range pkg.Links {
			link = strings.ToLower(strings.TrimSuffix(strings.TrimRight(link, "/"), ".git"))
			if _, exists := linkBlocklist[link]; exists {
				continue
			}

			normalizedName := NormalizePackageName(pkg.Name)

			if _, exists := links[link]; !exists {
				links[link] = make(map[string]bool)
			}
			links[link][normalizedName] = true

			if vendorProduct := extractVendorProduct(link); vendorProduct != "" {
				vendorProductToPkg[vendorProduct] = append(vendorProductToPkg[vendorProduct], normalizedName)
			}
		}
	}

	processedLinks := map[string][]string{}
	for link, pkgs := range links {
		processedLinks[link] = make([]string, 0, len(pkgs))
		for pkg := range pkgs {
			processedLinks[link] = append(processedLinks[link], pkg)
		}
	}

	return processedLinks, vendorProductToPkg
}

// processVersions takes a pypi_versions.json and returns a map of packages to versions.
func processVersions(versionsSource []pypiVersions) map[string][]string {
	versions := map[string][]string{}
	for _, data := range versionsSource {
		versions[NormalizePackageName(data.Name)] = data.Versions
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

func (p *PyPI) Matches(cve cves.CVE, falsePositives *triage.FalsePositives) []string {
	matches := []string{}
	for _, reference := range cve.References {
		// If there is a PyPI link, it must be a Python package. These take precedence.
		if pkg := extractPyPIProject(reference.Url); pkg != "" {
			log.Printf("Matched via PyPI link: %s", reference.Url)
			matches = append(matches, pkg)
		}
	}
	if len(matches) != 0 {
		return processMatches(matches)
	}

	for _, reference := range cve.References {
		// Otherwise try to cross-reference the link against our set of known links.
		pkgs := p.matchesPackage(reference.Url, cve, falsePositives)
		matches = append(matches, pkgs...)
	}
	if len(matches) != 0 {
		return processMatches(matches)
	}

	// As a last resort, extract the vendor and product from the CPE and try to match that
	// against vendor/product combinations extracted from e.g. GitHub links.
	cpes := cves.CPEs(cve)
	if len(cpes) == 0 {
		return processMatches(matches)
	}

	cpe := strings.Split(cpes[0], ":")
	if len(cpe) < 5 {
		return processMatches(matches)
	}

	vendorProduct := cpe[3] + "/" + cpe[4]
	if pkgs, exists := p.vendorProductToPkg[vendorProduct]; exists {
		for _, pkg := range pkgs {
			if p.finalPkgCheck(cve, pkg, falsePositives) {
				matches = append(matches, pkg)
			}
		}
	}
	return processMatches(matches)
}

func (p *PyPI) PackageURL(pkg string) string {
	// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pypi
	// Example: pkg:pypi/django-allauth
	normalizedName := NormalizePackageName(pkg)
	return "pkg:pypi/" + normalizedName
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
	desc := strings.ToLower(cves.EnglishDescription(cve.Descriptions))
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
	log.Printf("Matched description for %s", pkg)

	if falsePositives.CheckPackage(pkg) && !strings.Contains(desc, "python") {
		// If this package is listed as a false positive, and the description does not
		// mention "python" anywhere, it's most likely a true false positive.
		return false
	}

	// Finally check that the package still exists.
	return p.packageExists(pkg)
}

// matchesPackage checks if a given reference link matches a PyPI package.
func (p *PyPI) matchesPackage(link string, cve cves.CVE, falsePositives *triage.FalsePositives) []string {
	pkgs := []string{}
	u, err := url.Parse(strings.ToLower(link))
	if err != nil {
		return pkgs
	}

	// Repeatedly strip the last component in the URL.
	pathParts := strings.Split(u.Path, "/")
	for i := len(pathParts); i > 0; i-- {
		u.Path = strings.Join(pathParts[0:i], "/")
		fullURL := strings.TrimSuffix(u.String(), ".git")

		candidates, exists := p.links[fullURL]
		if !exists {
			candidates, exists = p.links[fullURL+"/"]
		}
		if !exists {
			continue
		}

		// Check that the package still exists on PyPI.
		for _, pkg := range candidates {
			log.Printf("Got potential match for %s: %s", fullURL, pkg)
			if p.finalPkgCheck(cve, pkg, falsePositives) {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return pkgs
}

func extractPyPIProject(link string) string {
	// Example: https://pypi.org/project/tensorflow
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}

	parts := strings.Split(u.Path, "/")

	switch u.Host {
	// Example: https://pypi.org/project/tensorflow
	case "pypi.org":
		if len(parts) < 3 || (parts[1] != "project" && parts[1] != "simple") {
			return ""
		}
		return NormalizePackageName(parts[2])
		// Example: https://pypi.python.org/pypi/tensorflow
	case "pypi.python.org":
		if len(parts) < 3 || parts[1] != "pypi" {
			return ""
		}
		return NormalizePackageName(parts[2])
	case "upload.pypi.org":
		if len(parts) < 3 || parts[1] != "legacy" {
			return ""
		}
		return NormalizePackageName(parts[2])
	}

	return ""
}
