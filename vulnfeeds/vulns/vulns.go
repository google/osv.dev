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
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
			Type: "GIT",
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
	PkgName           string                 `json:"pkg_name,omitempty" yaml:"pkg_name,omitempty"`
	Ecosystem         string                 `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty"`
	PURL              string                 `json:"purl,omitempty" yaml:"purl,omitempty"`
	VersionInfo       models.VersionInfo     `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty" yaml:"ecosystem_specific,omitempty"`
}

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
// It prioritizes newer CVSS versions.
func getBestSeverity(metricsData any) (string, osvschema.SeverityType) {
	switch md := metricsData.(type) {
	case *cves.CVEItemMetrics:
		if md == nil {
			return "", ""
		}
		// Prioritize CVSS v3.1 over v3.0 from the Primary scorer.
		for _, metric := range md.CVSSMetricV31 {
			if metric.Type == "Primary" && metric.CVSSData.VectorString != "" {
				return metric.CVSSData.VectorString, osvschema.SeverityCVSSV3
			}
		}
		for _, metric := range md.CVSSMetricV30 {
			if metric.Type == "Primary" && metric.CVSSData.VectorString != "" {
				return metric.CVSSData.VectorString, osvschema.SeverityCVSSV3
			}
		}
	case []cves.Metrics:
		// Define a prioritized list of checks.
		checks := []struct {
			getVectorString func(cves.Metrics) string
			severityType    osvschema.SeverityType
		}{
			{func(m cves.Metrics) string { return m.CVSSV4_0.VectorString }, osvschema.SeverityCVSSV4},
			{func(m cves.Metrics) string { return m.CVSSV3_1.VectorString }, osvschema.SeverityCVSSV3},
			{func(m cves.Metrics) string { return m.CVSSV3_0.VectorString }, osvschema.SeverityCVSSV3},
		}

		for _, check := range checks {
			for _, m := range md {
				if vectorString := check.getVectorString(m); vectorString != "" {
					return vectorString, check.severityType
				}
			}
		}
	}
	return "", ""
}

// AddSeverity adds CVSS severity information to the OSV vulnerability object.
// It uses the highest available CVSS score from the underlying CVE record.
func (v *Vulnerability) AddSeverity(metricsData any) {
	bestVectorString, severityType := getBestSeverity(metricsData)

	if bestVectorString == "" {
		return
	}

	v.Severity = append(v.Severity, osvschema.Severity{
		Type:  severityType,
		Score: bestVectorString,
	})
}

func (v *Vulnerability) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func (v *Vulnerability) ToYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	return encoder.Encode(v)
}

func cve5timestampToTime(timestamp string) (time.Time, error) {
	return cves.ParseCVE5Timestamp(timestamp)
}

// ClassifyReferenceLink infers the OSV schema's reference type for a given URL.
// See https://ossf.github.io/osv-schema/#references-field
// It uses tags first before resorting to inference by shape.
func ClassifyReferenceLink(link string, tag string) osvschema.ReferenceType {
	switch tag {
	case "Patch":
		return osvschema.ReferenceFix
	case "Exploit":
		return osvschema.ReferenceEvidence
	case "Mailing List":
		return osvschema.ReferenceArticle
	case "Issue Tracking":
		return osvschema.ReferenceReport
	case "Vendor Advisory", "Third Party Advisory", "VDB Entry":
		return osvschema.ReferenceAdvisory
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

func ExtractReferencedVulns(id cves.CVEID, cveID cves.CVEID, references []cves.Reference) ([]string, []string) {
	var aliases []string
	var related []string
	if id != cves.CVEID(cveID) {
		aliases = append(aliases, string(cves.CVEID(cveID)))
	}

	var GHSAs []string
	var SYNKs []string
	for _, reference := range references {
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

	return unique(aliases), unique(related)
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

// ClassifyReferences annotates reference links based on their tags or their shape.
func ClassifyReferences(refs []cves.Reference) []osvschema.Reference {
	var references []osvschema.Reference
	for _, reference := range refs {
		if len(reference.Tags) > 0 {
			for _, tag := range reference.Tags {
				references = append(references, osvschema.Reference{
					Type: ClassifyReferenceLink(reference.Url, tag),
					URL:  reference.Url,
				})
			}
		} else {
			references = append(references, osvschema.Reference{
				Type: ClassifyReferenceLink(reference.Url, ""),
				URL:  reference.Url,
			})
		}
	}
	references = unique(references)
	sort.SliceStable(references, func(i, j int) bool {
		return references[i].Type < references[j].Type
	})
	return references
}

// FromCVE creates a minimal OSV object from a given CVE and id.
// Leaves affected and version fields empty to be filled in later with AddPkgInfo
// There are two id fields passed in as one of the users of this field (PyPi) sometimes has a different id than the CVEID
// and the ExtractReferencedVulns function uses these in a check to add the other ID as an alias.
func FromCVE(id cves.CVEID, cveID cves.CVEID, references []cves.Reference, descriptions []cves.LangString, publishedDate time.Time, modifiedDate time.Time, metrics any) *Vulnerability {
	aliases, related := ExtractReferencedVulns(id, cveID, references)
	v := Vulnerability{}
	v.ID = string(id)
	v.Details = cves.EnglishDescription(descriptions)
	v.Aliases = aliases
	v.Related = related
	v.Published = publishedDate
	v.Modified = modifiedDate
	v.References = ClassifyReferences(references)
	v.AddSeverity(metrics)
	return &v
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
func CVEIsDisputed(v *Vulnerability, cveList string) (time.Time, error) {
	// iff the v.ID starts with a CVE...
	// 	Try to make an HTTP request for the CVE record in the CVE List
	// 	iff .containers.cna.tags contains "disputed"
	//		return .containers.cna.providerMetadata.dateUpdated, formatted for use in the Withdrawn field.
	if !strings.HasPrefix(v.ID, "CVE-") {
		return time.Time{}, ErrVulnNotACVE
	}

	CVEParts := strings.Split(v.ID, "-")[1:3]
	// Replace the last three digits of the CVE ID with "xxx".
	CVEYear, CVEIndexShard := CVEParts[0], CVEParts[1][:len(CVEParts[1])-3]+"xxx"

	// cvelistV5/cves/2023/23xxx/CVE-2023-23127.json
	CVEListFile := path.Join(cveList, CVEListBasePath, CVEYear, CVEIndexShard, v.ID+".json")

	f, err := os.Open(CVEListFile)

	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, &VulnsCVEListError{CVEListFile, err}
	}

	defer f.Close()

	CVE := &cves.CVE5{}

	if err := json.NewDecoder(f).Decode(&CVE); err != nil {
		return time.Time{}, &VulnsCVEListError{CVEListFile, err}
	}

	if slices.Contains(CVE.Containers.CNA.Tags, "disputed") {
		modified, err := cve5timestampToTime(CVE.Containers.CNA.ProviderMetadata.DateUpdated)
		return modified, err
	}

	return time.Time{}, nil
}
