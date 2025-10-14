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

// Package vulns contains helper functions for creating OSV vulnerability reports.
package vulns

import (
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const CVEListBasePath = "cves"

var ErrVulnNotACVE = errors.New("not a CVE")

type CVEListError struct {
	URL string
	Err error
}

// Error returns the string representation of a CVEListError.
func (e *CVEListError) Error() string {
	return e.URL + ": " + e.Err.Error()
}

type QualityCheck int

// String returns the string representation of a QualityCheck.
func (q QualityCheck) String() string {
	return [...]string{
		"QualityUnknown",
		"Success",
		"Spaces",
		"Empty",
		"Filler",
	}[q]
}

// AtLeast returns true if the quality is at least as good as the other quality.
// Lower values are considered better quality.
func (q QualityCheck) AtLeast(other QualityCheck) bool {
	return q <= other
}

const (
	// Set of enums for categorizing c.
	QualityUnknown QualityCheck = iota // Shouldn't happen
	Success                            // No determinable quality issue
	Spaces                             // Contains space characters
	Empty                              // Contains no entry
	Filler                             // Has been determined to be a filler word

)

// AttachExtractedVersionInfo converts the models.VersionInfo struct to OSV GIT and ECOSYSTEM AffectedRanges and AffectedPackage.
func AttachExtractedVersionInfo(affected *osvschema.Affected, version models.VersionInfo) {
	// commit holds a commit hash of one of the supported commit types.
	type commit struct {
		commitType models.CommitType
		hash       string
	}
	// Collect the commits of the supported types for each repo.
	repoToCommits := map[string][]commit{}

	unfixed := true
	for _, ac := range version.AffectedCommits {
		if ac.Introduced != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: models.Introduced, hash: ac.Introduced})
		}
		if ac.Fixed != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: models.Fixed, hash: ac.Fixed})
			unfixed = false
		}
		if ac.Limit != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: models.Limit, hash: ac.Limit})
		}
		if ac.LastAffected != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: models.LastAffected, hash: ac.LastAffected})
		}
	}

	for repo, commits := range repoToCommits {
		gitRange := osvschema.Range{
			Type: osvschema.RangeGit,
			Repo: repo,
		}
		// We're not always able to determine when a vulnerability is introduced, and may need to default to the dawn of time.
		addedIntroduced := false
		for _, commit := range commits {
			if commit.commitType == models.Introduced {
				gitRange.Events = append(gitRange.Events, osvschema.Event{Introduced: commit.hash})
				addedIntroduced = true
			}
			if commit.commitType == models.Fixed {
				gitRange.Events = append(gitRange.Events, osvschema.Event{Fixed: commit.hash})
			}
			if commit.commitType == models.Limit {
				gitRange.Events = append(gitRange.Events, osvschema.Event{Limit: commit.hash})
			}
			// Only add any LastAffectedCommits in the absence of
			// any FixCommits to maintain schema compliance.
			if commit.commitType == models.LastAffected && unfixed {
				gitRange.Events = append(gitRange.Events, osvschema.Event{LastAffected: commit.hash})
			}
		}
		if !addedIntroduced {
			// Prepending not strictly necessary, but seems nicer to have the Introduced first in the list.
			gitRange.Events = append([]osvschema.Event{{Introduced: "0"}}, gitRange.Events...)
		}
		affected.Ranges = append(affected.Ranges, gitRange)
	}

	// Adding an ECOSYSTEM version range only makes sense if we have package information.
	if affected.Package == (osvschema.Package{}) {
		return
	}

	versionRange := osvschema.Range{
		Type: "ECOSYSTEM",
	}
	seenIntroduced := map[string]bool{}
	seenFixed := map[string]bool{}

	for _, v := range version.AffectedVersions {
		var introduced string
		if v.Introduced == "" {
			introduced = "0"
		} else {
			introduced = v.Introduced
		}

		if _, seen := seenIntroduced[introduced]; !seen {
			versionRange.Events = append(versionRange.Events, osvschema.Event{
				Introduced: introduced,
			})
			seenIntroduced[introduced] = true
		}

		if _, seen := seenFixed[v.Fixed]; v.Fixed != "" && !seen {
			versionRange.Events = append(versionRange.Events, osvschema.Event{
				Fixed: v.Fixed,
			})
			seenFixed[v.Fixed] = true
		}
	}
	if len(version.AffectedVersions) > 0 {
		affected.Ranges = append(affected.Ranges, versionRange)
	}
}

// PackageInfo is an intermediate struct to ease generating Vulnerability structs.
type PackageInfo struct {
	PkgName           string             `json:"pkg_name,omitempty"           yaml:"pkg_name,omitempty"`
	Ecosystem         string             `json:"ecosystem,omitempty"          yaml:"ecosystem,omitempty"`
	PURL              string             `json:"purl,omitempty"               yaml:"purl,omitempty"`
	VersionInfo       models.VersionInfo `json:"fixed_version,omitempty"      yaml:"fixed_version,omitempty"`
	EcosystemSpecific map[string]any     `json:"ecosystem_specific,omitempty" yaml:"ecosystem_specific,omitempty"`
}

// ToJSON serializes the PackageInfo to JSON.
func (pi *PackageInfo) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(pi)
}

type Vulnerability struct {
	osvschema.Vulnerability
}

// AddPkgInfo converts a PackageInfo struct to the corresponding Affected and adds it to the OSV vulnerability object.
func (v *Vulnerability) AddPkgInfo(pkgInfo PackageInfo) {
	affected := osvschema.Affected{}

	if pkgInfo.PkgName != "" && pkgInfo.Ecosystem != "" {
		affected.Package = osvschema.Package{
			Name:      pkgInfo.PkgName,
			Ecosystem: pkgInfo.Ecosystem,
			Purl:      pkgInfo.PURL,
		}
	}

	// Aggregate commits by their repo, and synthesize a zero introduced commit if necessary.
	if len(pkgInfo.VersionInfo.AffectedCommits) > 0 {
		gitCommitRangesByRepo := map[string]osvschema.Range{}

		hasAddedZeroIntroduced := make(map[string]bool)

		for _, ac := range pkgInfo.VersionInfo.AffectedCommits {
			entry, ok := gitCommitRangesByRepo[ac.Repo]
			// Create the stub for the repo if necessary.
			if !ok {
				entry = osvschema.Range{
					Type:   osvschema.RangeGit,
					Events: []osvschema.Event{},
					Repo:   ac.Repo,
				}

				if !pkgInfo.VersionInfo.HasIntroducedCommits(ac.Repo) && !hasAddedZeroIntroduced[ac.Repo] {
					// There was no explicitly defined introduced commit, so create one at 0.
					entry.Events = append(entry.Events,
						osvschema.Event{
							Introduced: "0",
						},
					)
					hasAddedZeroIntroduced[ac.Repo] = true
				}
			}

			if ac.Introduced != "" {
				entry.Events = append(entry.Events, osvschema.Event{Introduced: ac.Introduced})
			}
			if ac.Fixed != "" {
				entry.Events = append(entry.Events, osvschema.Event{Fixed: ac.Fixed})
			}
			if ac.LastAffected != "" {
				entry.Events = append(entry.Events, osvschema.Event{LastAffected: ac.LastAffected})
			}
			if ac.Limit != "" {
				entry.Events = append(entry.Events, osvschema.Event{Limit: ac.Limit})
			}
			gitCommitRangesByRepo[ac.Repo] = entry
		}

		for repo := range gitCommitRangesByRepo {
			affected.Ranges = append(affected.Ranges, gitCommitRangesByRepo[repo])
		}
	}

	if len(pkgInfo.VersionInfo.AffectedVersions) > 0 {
		versionRange := osvschema.Range{
			Type:   osvschema.RangeEcosystem,
			Events: []osvschema.Event{},
		}
		hasIntroduced := false
		for _, av := range pkgInfo.VersionInfo.AffectedVersions {
			if av.Introduced != "" {
				hasIntroduced = true
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Introduced: av.Introduced,
				})
			}
			if av.Fixed != "" {
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Fixed: av.Fixed,
				})
			}
			if av.LastAffected != "" {
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					LastAffected: av.LastAffected,
				})
			}
		}

		if !hasIntroduced {
			// If no introduced entry, add one with special value of 0 to indicate
			// all versions before fixed is affected
			versionRange.Events = append([]osvschema.Event{{
				Introduced: "0",
			}}, versionRange.Events...)
		}
		affected.Ranges = append(affected.Ranges, versionRange)
	}

	// Sort affected[].ranges (by type) for stability.
	// https://ossf.github.io/osv-schema/#requirements
	slices.SortFunc(affected.Ranges, func(a, b osvschema.Range) int {
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		// Sort by repo within the same (GIT) typed range.
		return cmp.Compare(a.Repo, b.Repo)
	})

	affected.EcosystemSpecific = pkgInfo.EcosystemSpecific
	v.Affected = append(v.Affected, affected)
}

// getBestSeverity finds the best CVSS severity vector from the provided metrics data.
// It prioritizes newer CVSS versions and "Primary" sources.
func getBestSeverity(metricsData *cves.CVEItemMetrics) (string, osvschema.SeverityType) {
	// Define search passes. First pass for "Primary", second for any.
	for _, primaryOnly := range []bool{true, false} {
		// Inside each pass, prioritize v4.0 over v3.1 over v3.0.
		for _, metric := range metricsData.CVSSMetricV4 {
			if (!primaryOnly || metric.Type == "Primary") && metric.CVSSData.VectorString != "" {
				return metric.CVSSData.VectorString, osvschema.SeverityCVSSV4
			}
		}
		for _, metric := range metricsData.CVSSMetricV31 {
			if (!primaryOnly || metric.Type == "Primary") && metric.CVSSData.VectorString != "" {
				return metric.CVSSData.VectorString, osvschema.SeverityCVSSV3
			}
		}
		for _, metric := range metricsData.CVSSMetricV30 {
			if (!primaryOnly || metric.Type == "Primary") && metric.CVSSData.VectorString != "" {
				return metric.CVSSData.VectorString, osvschema.SeverityCVSSV3
			}
		}
	}

	return "", ""
}

// AddSeverity adds CVSS severity information to the OSV vulnerability object.
// It uses the highest available CVSS score from the underlying CVE record.
func (v *Vulnerability) AddSeverity(metricsData *cves.CVEItemMetrics) {
	bestVectorString, severityType := getBestSeverity(metricsData)

	if bestVectorString == "" {
		return
	}

	v.Severity = append(v.Severity, osvschema.Severity{
		Type:  severityType,
		Score: bestVectorString,
	})
}

// ToJSON serializes the Vulnerability to JSON.
func (v *Vulnerability) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(v)
}

// ToYAML serializes the Vulnerability to YAML.
func (v *Vulnerability) ToYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	return encoder.Encode(v)
}

// ClassifyReferenceLink infers the OSV schema's reference type for a given URL.
// See https://ossf.github.io/osv-schema/#references-field
// It uses tags first before resorting to inference by shape.
// Supports both NVD-style and CVEList V5 tags.
func ClassifyReferenceLink(link string, tag string) osvschema.ReferenceType {
	normalizedTag := strings.ToLower(tag)
	normalizedTag = strings.ReplaceAll(normalizedTag, " ", "-")

	switch normalizedTag {
	case "patch", "patch-related", "fix":
		return osvschema.ReferenceFix
	case "exploit":
		return osvschema.ReferenceEvidence
	case "mailing-list", "technical-description", "article", "blog", "news":
		return osvschema.ReferenceArticle
	case "issue-tracking", "permissions-required", "report", "bug-report":
		return osvschema.ReferenceReport
	case "vendor-advisory", "third-party-advisory", "vdb-entry", "release-notes", "advisory", "security-advisory":
		return osvschema.ReferenceAdvisory
	}

	// Check if URL is git repo
	if strings.HasPrefix(link, "git://") || strings.HasSuffix(link, ".git") {
		return osvschema.ReferencePackage
	}

	u, err := url.Parse(link)
	if err != nil {
		return osvschema.ReferenceWeb
	}

	pathParts := strings.Split(u.Path, "/")

	// Index 0 will always be "", so the length must be at least 2 to be relevant
	if len(pathParts) >= 2 {
		if u.Host == "github.com" {
			// Example: https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "commit" {
				return osvschema.ReferenceFix
			}

			// Example: https://github.com/advisories/GHSA-fr26-qjc8-mvjx
			// Example: https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "advisories" {
				return osvschema.ReferenceAdvisory
			}

			// Example: https://github.com/Netflix/lemur/issues/117
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "issues" {
				return osvschema.ReferenceReport
			}

			// Example: https://github.com/tensorflow/tensorflow/pull/66450
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "pull" {
				return osvschema.ReferenceFix
			}

			// Example: https://github.com/git/git/releases/tag/v2.45.2
			if len(pathParts) >= 3 && pathParts[len(pathParts)-1] == "releases" {
				return osvschema.ReferencePackage
			}

			// Example: https://github.com/google/osv-scanner (general repo link)
			// If it's just a 2-part path (user/repo), consider it a package/project reference
			if len(pathParts) == 3 && pathParts[1] != "" && pathParts[2] != "" {
				return osvschema.ReferencePackage
			}
		}

		// Support for other Git hosting platforms
		if u.Host == "gitlab.com" || strings.Contains(u.Host, "gitlab") {
			// Example: https://gitlab.com/gitlab-org/gitlab/-/commit/9d78aa57285961003ba767ad43642b18973a4678
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "commit" {
				return osvschema.ReferenceFix
			}
			// Example: https://gitlab.com/gitlab-org/gitlab/-/issues/432139
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "issues" {
				return osvschema.ReferenceReport
			}
			// Example: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/162237
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "merge_requests" {
				return osvschema.ReferenceFix
			}
			// Example: https://gitlab.com/qemu-project/qemu
			if len(pathParts) >= 3 && pathParts[1] != "" && pathParts[2] != "" && len(pathParts) <= 4 {
				return osvschema.ReferencePackage
			}
		}

		if u.Host == "bitbucket.org" {
			// Example: https://bitbucket.org/JustWalters/b-b-enhancement/commits/cf9a571dc3f03134444b2c8f2198db9174110365
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "commits" {
				return osvschema.ReferenceFix
			}
			// Example: https://bitbucket.org/JustWalters/b-b-enhancement/issues/1/last-post-logs-user-out-when-on-global
			if len(pathParts) >= 3 && pathParts[len(pathParts)-2] == "issues" {
				return osvschema.ReferenceReport
			}
			// Example: https://bitbucket.org/cstshane/lo5_b
			if len(pathParts) == 3 && pathParts[1] != "" && pathParts[2] != "" {
				return osvschema.ReferencePackage
			}
		}

		if u.Host == "snyk.io" {
			//Example: https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329
			if pathParts[1] == "vuln" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "nvd.nist.gov" {
			//Example: https://nvd.nist.gov/vuln/detail/CVE-2021-23336
			if len(pathParts) == 4 && pathParts[1] == "vuln" && pathParts[2] == "detail" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "www.debian.org" {
			//Example: https://www.debian.org/security/2021/dsa-4878
			if pathParts[1] == "security" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "usn.ubuntu.com" {
			//Example: https://usn.ubuntu.com/usn/usn-4661-1
			if pathParts[1] == "usn" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "www.ubuntu.com" {
			//Example: http://www.ubuntu.com/usn/USN-2915-2
			if pathParts[1] == "usn" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "ubuntu.com" {
			//Example: https://ubuntu.com/security/notices/USN-5124-1
			if pathParts[1] == "security" && pathParts[2] == "notices" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "rhn.redhat.com" {
			//Example: http://rhn.redhat.com/errata/RHSA-2016-0504.html
			if pathParts[1] == "errata" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "access.redhat.com" {
			//Example: https://access.redhat.com/errata/RHSA-2017:1499
			if pathParts[1] == "errata" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "security.gentoo.org" {
			//Example: https://security.gentoo.org/glsa/202003-45
			if len(pathParts) >= 2 && pathParts[len(pathParts)-2] == "glsa" {
				return osvschema.ReferenceAdvisory
			}
		}

		if u.Host == "pypi.org" {
			//Example: "https://pypi.org/project/flask"
			if pathParts[1] == "project" {
				return osvschema.ReferencePackage
			}
		}
	}

	if strings.Contains(link, "advisory") || strings.Contains(link, "advisories") {
		return osvschema.ReferenceAdvisory
	}

	if strings.Contains(link, "bugzilla") {
		return osvschema.ReferenceReport
	}

	if strings.Contains(link, "blog") {
		return osvschema.ReferenceArticle
	}

	return osvschema.ReferenceWeb
}

// ExtractReferencedVulns extracts other vulnerability IDs from a CVE's references
// to place them into the aliases and related fields.
func ExtractReferencedVulns(id cves.CVEID, cveID cves.CVEID, references []cves.Reference) ([]string, []string) {
	var aliases []string
	var related []string
	if id != cveID {
		aliases = append(aliases, string(cveID))
	}

	var GHSAs []string
	var SYNKs []string
	for _, reference := range references {
		u, err := url.Parse(reference.URL)
		if err == nil {
			pathParts := strings.Split(u.Path, "/")

			// Index 0 will always be "", so the length must be at least 3 here to be relevant
			if len(pathParts) >= 3 {
				if u.Host == "github.com" {
					// Example: https://github.com/advisories/GHSA-fr26-qjc8-mvjx
					// Example: https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4
					if pathParts[len(pathParts)-2] == "advisories" {
						a := pathParts[len(pathParts)-1]

						if string(id) != a && strings.HasPrefix(a, "GHSA-") {
							GHSAs = append(GHSAs, a)
						}
					}
				}

				if u.Host == "snyk.io" {
					//Example: https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329
					if pathParts[1] == "vuln" {
						a := pathParts[len(pathParts)-1]
						if string(id) != a && strings.HasPrefix(a, "SNYK-") {
							SYNKs = append(SYNKs, a)
						}
					}
				}
			}
		}
	}

	// A CVE should have only one GHSA as an alias
	// If multiple GHSAs are associated with a CVE,
	// it can potentially cause one CVE to be aliased to other CVEs, which is most likely incorrect.
	if len(GHSAs) > 1 {
		related = append(related, GHSAs...)
	} else {
		aliases = append(aliases, GHSAs...)
	}
	if len(SYNKs) > 1 {
		related = append(related, SYNKs...)
	} else {
		aliases = append(aliases, SYNKs...)
	}

	// TODO(jesslowe): Check if references to other CVEs exist in the description and add to related

	return Unique(aliases), Unique(related)
}

// Unique removes duplicate elements from a slice.
func Unique[T comparable](s []T) []T {
	inResult := make(map[T]bool)
	var result []T
	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}

	return result
}

// ClassifyReferences annotates reference links based on their tags or their shape.
func ClassifyReferences(refs []cves.Reference) []osvschema.Reference {
	var references []osvschema.Reference
	for _, reference := range refs {
		if len(reference.Tags) > 0 {
			for _, tag := range reference.Tags {
				references = append(references, osvschema.Reference{
					Type: ClassifyReferenceLink(reference.URL, tag),
					URL:  reference.URL,
				})
			}
		} else {
			references = append(references, osvschema.Reference{
				Type: ClassifyReferenceLink(reference.URL, ""),
				URL:  reference.URL,
			})
		}
	}
	references = Unique(references)
	sort.SliceStable(references, func(i, j int) bool {
		return references[i].Type < references[j].Type
	})

	return references
}

// FromNVDCVE creates a minimal OSV object from a given CVE and id.
// Leaves affected and version fields empty to be filled in later with AddPkgInfo
// There are two id fields passed in as one of the users of this field (PyPi) sometimes has a different id than the CVEID
// and the ExtractReferencedVulns function uses these in a check to add the other ID as an alias.
func FromNVDCVE(id cves.CVEID, cve cves.CVE) *Vulnerability {
	aliases, related := ExtractReferencedVulns(id, cve.ID, cve.References)
	v := Vulnerability{}
	v.ID = string(id)
	v.Details = cves.EnglishDescription(cve.Descriptions)
	v.Aliases = aliases
	v.Related = related
	v.Published = cve.Published.Time
	v.Modified = cve.LastModified.Time
	v.References = ClassifyReferences(cve.References)
	v.AddSeverity(cve.Metrics)

	return &v
}

// GetCPEs extracts CPE strings from a slice of cves.CPE.
// Returns array of CPE strings and array of notes.
func GetCPEs(cpeApplicability []cves.CPE) ([]string, []string) {
	var CPEs []string
	var notes []string
	for _, c := range cpeApplicability {
		for _, node := range c.Nodes {
			if node.Operator != "OR" {
				notes = append(notes, "Node found without OR operator")
				continue
			}
			for _, match := range node.CPEMatch {
				CPEs = append(CPEs, match.Criteria)
			}
		}
	}

	return CPEs, notes
}

// FromYAML deserializes a Vulnerability from a YAML reader.
func FromYAML(r io.Reader) (*Vulnerability, error) {
	decoder := yaml.NewDecoder(r)
	var vuln Vulnerability
	err := decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// FromJSON deserializes a Vulnerability from a JSON reader.
func FromJSON(r io.Reader) (*Vulnerability, error) {
	decoder := json.NewDecoder(r)
	var vuln Vulnerability
	err := decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// CheckQuality will return true if field text is not a filler text or otherwise empty
func CheckQuality(text string) QualityCheck {
	var fillerText = []string{
		"n/a", // common with mitre vulns
		"unknown",
		"unspecified",
		"not-known",
		"tbd",
		"to be determined",
		"-",
	}
	for _, filler := range fillerText {
		if strings.EqualFold(strings.TrimSpace(text), filler) {
			return Filler
		}
	}
	if text == "" {
		return Empty
	}

	if strings.Contains(text, " ") {
		return Spaces
	}

	return Success
}

// LoadAllCVEs loads the downloaded CVE's from the NVD database into memory.
func LoadAllCVEs(cvePath string) map[cves.CVEID]cves.Vulnerability {
	dir, err := os.ReadDir(cvePath)
	if err != nil {
		logger.Fatal("Failed to read dir", slog.String("path", cvePath), slog.Any("err", err))
	}

	vulnsChan := make(chan cves.Vulnerability)
	var wg sync.WaitGroup

	for _, entry := range dir {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		wg.Add(1)
		go func(filename string) {
			defer wg.Done()
			filePath := path.Join(cvePath, filename)
			file, err := os.Open(filePath)
			if err != nil {
				logger.Error("Failed to open CVE JSON", slog.String("path", filePath), slog.Any("err", err))
				return
			}
			defer file.Close()

			var nvdcve cves.CVEAPIJSON20Schema
			if err := json.NewDecoder(file).Decode(&nvdcve); err != nil {
				logger.Error("Failed to decode JSON", slog.String("file", filename), slog.Any("err", err))
				return
			}

			for _, item := range nvdcve.Vulnerabilities {
				vulnsChan <- item
			}
			logger.Info("Loaded "+filename, slog.String("cve", filename))
		}(entry.Name())
	}

	go func() {
		wg.Wait()
		close(vulnsChan)
	}()

	result := make(map[cves.CVEID]cves.Vulnerability)
	for item := range vulnsChan {
		result[item.CVE.ID] = item
	}

	return result
}

func FindSeverity(metricsData []cves.Metrics) osvschema.Severity {
	bestVectorString, severityType := getBestCVE5Severity(metricsData)
	severity := osvschema.Severity{}
	if bestVectorString == "" {
		return severity
	}

	severity = osvschema.Severity{
		Type:  severityType,
		Score: bestVectorString,
	}

	return severity
}

func getBestCVE5Severity(metricsData []cves.Metrics) (string, osvschema.SeverityType) {
	checks := []struct {
		getVectorString func(cves.Metrics) string
		severityType    osvschema.SeverityType
	}{
		{func(m cves.Metrics) string { return m.CVSSv4_0.VectorString }, osvschema.SeverityCVSSV4},
		{func(m cves.Metrics) string { return m.CVSSv3_1.VectorString }, osvschema.SeverityCVSSV3},
		{func(m cves.Metrics) string { return m.CVSSv3_0.VectorString }, osvschema.SeverityCVSSV3},
	}

	for _, check := range checks {
		for _, m := range metricsData {
			if vectorString := check.getVectorString(m); vectorString != "" {
				return vectorString, check.severityType
			}
		}
	}

	return "", ""
}
