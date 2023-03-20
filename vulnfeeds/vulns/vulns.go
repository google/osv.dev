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
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
)

type Event struct {
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Limit        string `json:"limit,omitempty" yaml:"limit,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

type Affected struct {
	Package  *AffectedPackage `json:"package,omitempty"`
	Ranges   []AffectedRange  `json:"ranges" yaml:"ranges"`
	Versions []string         `json:"versions,omitempty" yaml:"versions,omitempty"`
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

type Vulnerability struct {
	ID         string      `json:"id" yaml:"id"`
	Summary    string      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Details    string      `json:"details" yaml:"details"`
	Affected   []Affected  `json:"affected" yaml:"affected"`
	References []Reference `json:"references" yaml:"references"`
	Aliases    []string    `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Modified   string      `json:"modified" yaml:"modified"`
	Published  string      `json:"published" yaml:"published"`
}

func timestampToRFC3339(timestamp string) (string, error) {
	t, err := cves.ParseTimestamp(timestamp)
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

func extractAliases(id string, cve cves.CVE) []string {
	var aliases []string
	if id != cve.CVEDataMeta.ID {
		aliases = append(aliases, cve.CVEDataMeta.ID)
	}

	for _, reference := range cve.References.ReferenceData {
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

type PackageInfo struct {
	PkgName      string `json:"pkg_name"`
	Ecosystem    string `json:"ecosystem"`
	PURL         string `json:"purl"`
	FixedVersion string `json:"fixed_version"`
	FixedCommit  string `json:"fixed_commit"`
	Repo         string `json:"repo"`
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
func ClassifyReferences(refs cves.CVEReferences) []Reference {
	references := []Reference{}
	for _, reference := range refs.ReferenceData {
		if len(reference.Tags) > 0 {
			for _, tag := range reference.Tags {
				references = append(references, Reference{
					Type: ClassifyReferenceLink(reference.URL, tag),
					URL:  reference.URL,
				})
			}
		} else {
			references = append(references, Reference{
				Type: ClassifyReferenceLink(reference.URL, ""),
				URL:  reference.URL,
			})
		}
	}
	return unique(references)
}

// FromCVE creates a bare minimum OSV object from a given CVEItem and id.
// Leaves affected and version fields empty to be filled in later with AddPkgInfo
func FromCVE(id string, cve cves.CVEItem) (*Vulnerability, []string) {
	v := Vulnerability{
		ID:      id,
		Details: cves.EnglishDescription(cve.CVE),
		Aliases: extractAliases(id, cve.CVE),
	}
	var err error
	var notes []string
	v.Published, err = timestampToRFC3339(cve.PublishedDate)
	if err != nil {
		notes = append(notes, fmt.Sprintf("Failed to parse published date: %v\n", err))
	}

	v.Modified, err = timestampToRFC3339(cve.LastModifiedDate)
	if err != nil {
		notes = append(notes, fmt.Sprintf("Failed to parse modified date: %v\n", err))
	}

	v.References = ClassifyReferences(cve.CVE.References)
	return &v, notes
}

// AddPkgInfo adds affected package information to the OSV vulnerability object
func (v *Vulnerability) AddPkgInfo(pkgInfo PackageInfo) {
	affected := Affected{}
	affected.Package = &AffectedPackage{
		Name:      pkgInfo.PkgName,
		Ecosystem: pkgInfo.Ecosystem,
		Purl:      pkgInfo.PURL,
	}
	if pkgInfo.FixedVersion != "" {
		versionRange := AffectedRange{
			Type: "ECOSYSTEM",
			Events: []Event{
				{Introduced: "0"},
				{Fixed: pkgInfo.FixedVersion},
			},
		}
		affected.Ranges = append(affected.Ranges, versionRange)
	}

	if pkgInfo.FixedCommit != "" {
		versionRange := AffectedRange{
			Type: "GIT",
			Repo: pkgInfo.Repo,
			Events: []Event{
				{Introduced: "0"},
				{Fixed: pkgInfo.FixedCommit},
			},
		}
		affected.Ranges = append(affected.Ranges, versionRange)
	}
	v.Affected = append(v.Affected, affected)
}

// AttachExtractedVersionInfo adds version information extracted from CVEs onto
// the affected field
func (affected *Affected) AttachExtractedVersionInfo(version cves.VersionInfo) {
	// Synthetic enum of supported commit types.
	type CommitType int
	const (
		Introduced CommitType = iota
		Fixed
		Limit
		LastAffected
	)
	// commit holds a commit hash of one of the supported commit types.
	type commit struct {
		commitType CommitType
		hash       string
	}
	// Collect the commits of the supported types for each repo.
	repoToCommits := map[string][]commit{}

	for _, introducedCommit := range version.IntroducedCommits {
		repoToCommits[introducedCommit.Repo] = append(repoToCommits[introducedCommit.Repo], commit{commitType: Introduced, hash: introducedCommit.Commit})
	}

	for _, fixCommit := range version.FixCommits {
		repoToCommits[fixCommit.Repo] = append(repoToCommits[fixCommit.Repo], commit{commitType: Fixed, hash: fixCommit.Commit})
	}

	for _, limitCommit := range version.LimitCommits {
		repoToCommits[limitCommit.Repo] = append(repoToCommits[limitCommit.Repo], commit{commitType: Limit, hash: limitCommit.Commit})
	}

	for _, lastAffectedCommit := range version.LastAffectedCommits {
		repoToCommits[lastAffectedCommit.Repo] = append(repoToCommits[lastAffectedCommit.Repo], commit{commitType: LastAffected, hash: lastAffectedCommit.Commit})
	}

	for repo, commits := range repoToCommits {
		gitRange := AffectedRange{
			Type: "GIT",
			Repo: repo,
		}
		// We're not always able to determine when a vulnerability is introduced, and may need to default to the dawn of time.
		addedIntroduced := false
		for _, commit := range commits {
			if commit.commitType == Introduced {
				gitRange.Events = append(gitRange.Events, Event{Introduced: commit.hash})
				addedIntroduced = true
			}
			if commit.commitType == Fixed {
				gitRange.Events = append(gitRange.Events, Event{Fixed: commit.hash})
			}
			if commit.commitType == Limit {
				gitRange.Events = append(gitRange.Events, Event{Limit: commit.hash})
			}
			if commit.commitType == LastAffected {
				gitRange.Events = append(gitRange.Events, Event{LastAffected: commit.hash})
			}
		}
		if !addedIntroduced {
			// Prepending not strictly necessary, but seems nicer to have the Introduced first in the list.
			gitRange.Events = append([]Event{Event{Introduced: "0"}}, gitRange.Events...)
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

func FromYAML(r io.Reader) (*Vulnerability, error) {
	decoder := yaml.NewDecoder(r)
	var vuln Vulnerability
	err := decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

func (v *Vulnerability) ToYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	return encoder.Encode(v)
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

func (v *Vulnerability) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(v)
}
