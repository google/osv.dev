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

package vulns

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
)

const CVEListBasePath = "cves"

var ErrVulnNotACVE = errors.New("not a CVE")

type VulnsCVEListError struct {
	URL string
	Err error
}

func (e *VulnsCVEListError) Error() string {
	return e.URL + ": " + e.Err.Error()
}

type Event struct {
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Limit        string `json:"limit,omitempty" yaml:"limit,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

type Severity struct {
	Type  string `json:"type" yaml:"type"`
	Score string `json:"score" yaml:"score"`
}

type Affected struct {
	Package  *AffectedPackage `json:"package,omitempty"`
	Ranges   []AffectedRange  `json:"ranges" yaml:"ranges"`
	Versions []string         `json:"versions,omitempty" yaml:"versions,omitempty"`
}

// AttachExtractedVersionInfo converts the cves.VersionInfo struct to OSV GIT and ECOSYSTEM AffectedRanges and AffectedPackage.
func (affected *Affected) AttachExtractedVersionInfo(version cves.VersionInfo) {
	// commit holds a commit hash of one of the supported commit types.
	type commit struct {
		commitType cves.CommitType
		hash       string
	}
	// Collect the commits of the supported types for each repo.
	repoToCommits := map[string][]commit{}

	unfixed := true
	for _, ac := range version.AffectedCommits {
		if ac.Introduced != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: cves.Introduced, hash: ac.Introduced})
		}
		if ac.Fixed != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: cves.Fixed, hash: ac.Fixed})
			unfixed = false
		}
		if ac.Limit != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: cves.Limit, hash: ac.Limit})
		}
		if ac.LastAffected != "" {
			repoToCommits[ac.Repo] = append(repoToCommits[ac.Repo], commit{commitType: cves.LastAffected, hash: ac.LastAffected})
		}
	}

	for repo, commits := range repoToCommits {
		gitRange := AffectedRange{
			Type: "GIT",
			Repo: repo,
		}
		// We're not always able to determine when a vulnerability is introduced, and may need to default to the dawn of time.
		addedIntroduced := false
		for _, commit := range commits {
			if commit.commitType == cves.Introduced {
				gitRange.Events = append(gitRange.Events, Event{Introduced: commit.hash})
				addedIntroduced = true
			}
			if commit.commitType == cves.Fixed {
				gitRange.Events = append(gitRange.Events, Event{Fixed: commit.hash})
			}
			if commit.commitType == cves.Limit {
				gitRange.Events = append(gitRange.Events, Event{Limit: commit.hash})
			}
			// Only add any LastAffectedCommits in the absence of
			// any FixCommits to maintain schema compliance.
			if commit.commitType == cves.LastAffected && unfixed {
				gitRange.Events = append(gitRange.Events, Event{LastAffected: commit.hash})
			}
		}
		if !addedIntroduced {
			// Prepending not strictly necessary, but seems nicer to have the Introduced first in the list.
			gitRange.Events = append([]Event{{Introduced: "0"}}, gitRange.Events...)
		}
		affected.Ranges = append(affected.Ranges, gitRange)
	}

	// Adding an ECOSYSTEM version range only makes sense if we have package information.
	if affected.Package == nil {
		return
	}

	versionRange := AffectedRange{
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
			versionRange.Events = append(versionRange.Events, Event{
				Introduced: introduced,
			})
			seenIntroduced[introduced] = true
		}

		if _, seen := seenFixed[v.Fixed]; v.Fixed != "" && !seen {
			versionRange.Events = append(versionRange.Events, Event{
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
	PkgName     string           `json:"pkg_name,omitempty" yaml:"pkg_name,omitempty"`
	Ecosystem   string           `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty"`
	PURL        string           `json:"purl,omitempty" yaml:"purl,omitempty"`
	VersionInfo cves.VersionInfo `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
}

func (pi *PackageInfo) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(pi)
}

type AffectedPackage struct {
	Name      string `json:"name,omitempty" yaml:"name"`
	Ecosystem string `json:"ecosystem,omitempty" yaml:"ecosystem"`
	Purl      string `json:"purl,omitempty" yaml:"purl,omitempty"`
}

type AffectedRange struct {
	Type   string  `json:"type" yaml:"type"`
	Repo   string  `json:"repo,omitempty" yaml:"repo,omitempty"`
	Events []Event `json:"events" yaml:"events"`
}

type Reference struct {
	Type string `json:"type" yaml:"type"`
	URL  string `json:"url" yaml:"url"`
}

type References []Reference

func (r References) Len() int           { return len(r) }
func (r References) Less(i, j int) bool { return r[i].Type < r[j].Type }
func (r References) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

type Vulnerability struct {
	ID         string      `json:"id" yaml:"id"`
	Withdrawn  string      `json:"withdrawn,omitempty" yaml:"withdrawn,omitempty"`
	Summary    string      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Severity   []Severity  `json:"severity,omitempty" yaml:"severity,omitempty"`
	Details    string      `json:"details" yaml:"details"`
	Affected   []Affected  `json:"affected" yaml:"affected"`
	References []Reference `json:"references" yaml:"references"`
	Aliases    []string    `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Modified   string      `json:"modified" yaml:"modified"`
	Published  string      `json:"published" yaml:"published"`
}

// AddPkgInfo converts a PackageInfo struct to the corresponding AffectedRanges and adds them to the OSV vulnerability object.
func (v *Vulnerability) AddPkgInfo(pkgInfo PackageInfo) {
	affected := Affected{}

	if pkgInfo.PkgName != "" && pkgInfo.Ecosystem != "" {
		affected.Package = &AffectedPackage{
			Name:      pkgInfo.PkgName,
			Ecosystem: pkgInfo.Ecosystem,
			Purl:      pkgInfo.PURL,
		}
	}

	if len(pkgInfo.VersionInfo.AffectedCommits) > 0 {
		gitCommitRangesByRepo := map[string]AffectedRange{}

		hasAddedZeroIntroduced := make(map[string]bool)

		for _, ac := range pkgInfo.VersionInfo.AffectedCommits {
			entry, ok := gitCommitRangesByRepo[ac.Repo]
			if !ok {
				entry = AffectedRange{
					Type:   "GIT",
					Events: []Event{},
					Repo:   ac.Repo,
				}
			}

			if !pkgInfo.VersionInfo.HasIntroducedCommits(ac.Repo) && !hasAddedZeroIntroduced[ac.Repo] {
				// There was no explicitly defined introduced commit, so create one at 0
				entry.Events = append(entry.Events,
					Event{
						Introduced: "0",
					},
				)
				hasAddedZeroIntroduced[ac.Repo] = true
			}

			entry.Events = append(entry.Events,
				Event{
					Introduced:   ac.Introduced,
					Fixed:        ac.Fixed,
					LastAffected: ac.LastAffected,
					Limit:        ac.Limit,
				},
			)
			gitCommitRangesByRepo[ac.Repo] = entry
		}

		for repo := range gitCommitRangesByRepo {
			affected.Ranges = append(affected.Ranges, gitCommitRangesByRepo[repo])
		}
	}

	if len(pkgInfo.VersionInfo.AffectedVersions) > 0 {
		versionRange := AffectedRange{
			Type:   "ECOSYSTEM",
			Events: []Event{},
		}
		hasIntroduced := false
		for _, av := range pkgInfo.VersionInfo.AffectedVersions {
			if av.Introduced != "" {
				hasIntroduced = true
			}
			versionRange.Events = append(versionRange.Events, Event{
				Introduced:   av.Introduced,
				Fixed:        av.Fixed,
				LastAffected: av.LastAffected,
			})
		}

		if !hasIntroduced {
			// If no introduced entry, add one with special value of 0 to indicate
			// all versions before fixed is affected
			versionRange.Events = append([]Event{{
				Introduced: "0",
			}}, versionRange.Events...)
		}
		affected.Ranges = append(affected.Ranges, versionRange)
	}

	// Sort affected[].ranges (by type) for stability.
	// https://ossf.github.io/osv-schema/#requirements
	slices.SortFunc(affected.Ranges, func(a, b AffectedRange) int {
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		// Sort by repo within the same (GIT) typed range.
		return cmp.Compare(a.Repo, b.Repo)
	})

	v.Affected = append(v.Affected, affected)
}

// AddSeverity adds CVSS3 severity information to the OSV vulnerability object.
// It uses the highest available CVSS 3.x Primary score from the underlying CVE record.
func (v *Vulnerability) AddSeverity(CVEImpact *cves.CveItemMetrics) {
	if CVEImpact == nil {
		return
	}

	// Use the highest available of CvssMetric31, CvssMetric30
	// from the Primary scorer.
	var bestVectorString string

	for _, metric := range CVEImpact.CvssMetricV31 {
		if bestVectorString != "" {
			break
		}
		if metric.Type != "Primary" {
			continue
		}
		bestVectorString = metric.CvssData.VectorString
	}

	// No CVSS 3.1, try falling back to CVSS 3.0 if available.
	if bestVectorString == "" {
		for _, metric := range CVEImpact.CvssMetricV30 {
			if bestVectorString != "" {
				break
			}
			if metric.Type != "Primary" {
				continue
			}
			bestVectorString = metric.CvssData.VectorString
		}
	}

	// No luck, nothing to add.
	if bestVectorString == "" {
		return
	}

	severity := Severity{
		Type:  "CVSS_V3",
		Score: bestVectorString,
	}

	v.Severity = append(v.Severity, severity)
}

func (v *Vulnerability) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(v)
}

func (v *Vulnerability) ToYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	return encoder.Encode(v)
}

// func timestampToRFC3339(timestamp string) (string, error) {
// 	t, err := cves.ParseTimestamp(timestamp)
// 	if err != nil {
// 		return "", err
// 	}

// 	return t.Format(time.RFC3339), nil
// }

func CVE5timestampToRFC3339(timestamp string) (string, error) {
	t, err := cves.ParseCVE5Timestamp(timestamp)
	if err != nil {
		return "", err
	}

	return t.Format(time.RFC3339), nil
}

// For a given URL, infer the OSV schema's reference type of it.
// See https://ossf.github.io/osv-schema/#references-field
// Uses the tags first before resorting to inference by shape.

func ClassifyReferenceLink(link string, tag string) string {
	switch tag {
	case "Patch":
		return "FIX"
	case "Exploit":
		return "EVIDENCE"
	case "Mailing List":
		return "ARTICLE"
	case "Issue Tracking":
		return "REPORT"
	case "Vendor Advisory", "Third Party Avisory", "VDB Entry":
		return "ADVISORY"
	}

	u, err := url.Parse(link)
	if err != nil {
		return "WEB"
	}

	pathParts := strings.Split(u.Path, "/")

	// Index 0 will always be "", so the length must be at least 2 to be relevant
	if len(pathParts) >= 2 {
		if u.Host == "github.com" {
			// Example: https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5
			if pathParts[len(pathParts)-2] == "commit" {
				return "FIX"
			}

			// Example: https://github.com/advisories/GHSA-fr26-qjc8-mvjx
			// Example: https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4
			if pathParts[len(pathParts)-2] == "advisories" {
				return "ADVISORY"
			}

			// Example: https://github.com/Netflix/lemur/issues/117
			if pathParts[len(pathParts)-2] == "issues" {
				return "REPORT"
			}
		}

		if u.Host == "snyk.io" {
			//Example: https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329
			if pathParts[1] == "vuln" {
				return "ADVISORY"
			}
		}

		if u.Host == "nvd.nist.gov" {
			//Example: https://nvd.nist.gov/vuln/detail/CVE-2021-23336
			if len(pathParts) == 4 && pathParts[1] == "vuln" && pathParts[2] == "detail" {
				return "ADVISORY"
			}
		}

		if u.Host == "www.debian.org" {
			//Example: https://www.debian.org/security/2021/dsa-4878
			if pathParts[1] == "security" {
				return "ADVISORY"
			}
		}

		if u.Host == "usn.ubuntu.com" {
			//Example: https://usn.ubuntu.com/usn/usn-4661-1
			if pathParts[1] == "usn" {
				return "ADVISORY"
			}
		}

		if u.Host == "www.ubuntu.com" {
			//Example: http://www.ubuntu.com/usn/USN-2915-2
			if pathParts[1] == "usn" {
				return "ADVISORY"
			}
		}

		if u.Host == "ubuntu.com" {
			//Example: https://ubuntu.com/security/notices/USN-5124-1
			if pathParts[1] == "security" && pathParts[2] == "notices" {
				return "ADVISORY"
			}
		}

		if u.Host == "rhn.redhat.com" {
			//Example: http://rhn.redhat.com/errata/RHSA-2016-0504.html
			if pathParts[1] == "errata" {
				return "ADVISORY"
			}
		}

		if u.Host == "access.redhat.com" {
			//Example: https://access.redhat.com/errata/RHSA-2017:1499
			if pathParts[1] == "errata" {
				return "ADVISORY"
			}
		}

		if u.Host == "security.gentoo.org" {
			//Example: https://security.gentoo.org/glsa/202003-45
			if pathParts[len(pathParts)-2] == "glsa" {
				return "ADVISORY"
			}
		}

		if u.Host == "pypi.org" {
			//Example: "https://pypi.org/project/flask"
			if pathParts[1] == "project" {
				return "PACKAGE"
			}
		}
	}

	if strings.Contains(link, "advisory") || strings.Contains(link, "advisories") {
		return "ADVISORY"
	}

	if strings.Contains(link, "bugzilla") {
		return "REPORT"
	}

	if strings.Contains(link, "blog") {
		return "ARTICLE"
	}

	return "WEB"
}

func extractAliases(id string, cve cves.CveItem) []string {
	var aliases []string
	if id != string(cve.Id) {
		aliases = append(aliases, string(cve.Id))
	}

	for _, reference := range cve.References {
		u, err := url.Parse(reference.Url)
		if err == nil {
			pathParts := strings.Split(u.Path, "/")

			// Index 0 will always be "", so the length must be at least 3 here to be relevant
			if len(pathParts) >= 3 {
				if u.Host == "github.com" {
					// Example: https://github.com/advisories/GHSA-fr26-qjc8-mvjx
					// Example: https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4
					if pathParts[len(pathParts)-2] == "advisories" {
						a := pathParts[len(pathParts)-1]

						if id != a && strings.HasPrefix(a, "GHSA-") {
							aliases = append(aliases, a)
						}
					}
				}

				if u.Host == "snyk.io" {
					//Example: https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329
					if pathParts[1] == "vuln" {
						a := pathParts[len(pathParts)-1]

						if id != a && strings.HasPrefix(a, "SNYK-") {
							aliases = append(aliases, a)
						}
					}
				}
			}
		}
	}

	return aliases
}

func unique[T comparable](s []T) []T {
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

// Annotates reference links based on their tags or the shape of them.
func ClassifyReferences(refs []cves.Reference) (references References) {
	for _, reference := range refs {
		if len(reference.Tags) > 0 {
			for _, tag := range reference.Tags {
				references = append(references, Reference{
					Type: ClassifyReferenceLink(reference.Url, tag),
					URL:  reference.Url,
				})
			}
		} else {
			references = append(references, Reference{
				Type: ClassifyReferenceLink(reference.Url, ""),
				URL:  reference.Url,
			})
		}
	}
	references = unique(references)
	sort.Stable(references)
	return references
}

// FromCVE creates a minimal OSV object from a given CVEItem and id.
// Leaves affected and version fields empty to be filled in later with AddPkgInfo
func FromCVE(id string, cve cves.CveItem) (*Vulnerability, []string) {
	v := Vulnerability{
		ID:      id,
		Details: cves.EnglishDescription(cve),
		Aliases: extractAliases(id, cve),
	}
	var err error
	var notes []string
	v.Published = cve.Published.Format(time.RFC3339)
	if err != nil {
		notes = append(notes, fmt.Sprintf("Failed to parse published date: %v\n", err))
	}

	v.Modified = cve.LastModified.Format(time.RFC3339)
	if err != nil {
		notes = append(notes, fmt.Sprintf("Failed to parse modified date: %v\n", err))
	}

	v.References = ClassifyReferences(cve.References)
	v.AddSeverity(cve.Metrics)
	return &v, notes
}

func FromYAML(r io.Reader) (*Vulnerability, error) {
	decoder := yaml.NewDecoder(r)
	var vuln Vulnerability
	err := decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

func FromJSON(r io.Reader) (*Vulnerability, error) {
	decoder := json.NewDecoder(r)
	var vuln Vulnerability
	err := decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// CVEIsDisputed will return if the underlying CVE is disputed.
// It returns the CVE's CNA container's dateUpdated value if it is disputed.
// This can be used to set the Withdrawn field.
// It consults a local clone of https://github.com/CVEProject/cvelistV5 found in the location specified by cveList
func CVEIsDisputed(v *Vulnerability, cveList string) (modified string, e error) {
	// iff the v.ID starts with a CVE...
	// 	Try to make an HTTP request for the CVE record in the CVE List
	// 	iff .containers.cna.tags contains "disputed"
	//		return .containers.cna.providerMetadata.dateUpdated, formatted for use in the Withdrawn field.
	if !strings.HasPrefix(v.ID, "CVE-") {
		return "", ErrVulnNotACVE
	}

	CVEParts := strings.Split(v.ID, "-")[1:3]
	// Replace the last three digits of the CVE ID with "xxx".
	CVEYear, CVEIndexShard := CVEParts[0], CVEParts[1][:len(CVEParts[1])-3]+"xxx"

	// cvelistV5/cves/2023/23xxx/CVE-2023-23127.json
	CVEListFile := path.Join(cveList, CVEListBasePath, CVEYear, CVEIndexShard, v.ID+".json")

	f, err := os.Open(CVEListFile)

	if err != nil {
		return "", &VulnsCVEListError{"", err}
	}

	defer f.Close()

	decoder := json.NewDecoder(f)

	CVE := &cves.CVE5{}

	if err := decoder.Decode(&CVE); err != nil {
		return "", &VulnsCVEListError{"", err}
	}

	if slices.Contains(CVE.Containers.CNA.Tags, "disputed") {
		modified, err = CVE5timestampToRFC3339(CVE.Containers.CNA.ProviderMetadata.DateUpdated)
		return modified, err
	}

	return "", nil
}
