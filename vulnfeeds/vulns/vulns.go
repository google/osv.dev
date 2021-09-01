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
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/google/osv/vulnfeeds/cves"
)

type Event struct {
	Introduced string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Limit      string `json:"limit,omitempty" yaml:"limit,omitempty"`
}

type Affected struct {
	Package struct {
		Name      string `json:"name" yaml:"name"`
		Ecosystem string `json:"ecosystem" yaml:"ecosystem"`
	} `json:"package"`
	Ranges   []AffectedRange `json:"ranges" yaml:"ranges"`
	Versions []string        `json:"versions" yaml:"versions,omitempty"`
}

type AffectedRange struct {
	Type   string  `json:"type" yaml:"type"`
	Repo   string  `json:"repo,omitempty" yaml:"repo,omitempty"`
	Events []Event `json:"events", yaml:"events"`
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

func FromCVE(id string, cve cves.CVEItem, pkg, ecosystem, versionType string, validVersions []string) (*Vulnerability, []string) {
	var aliases []string
	if id != cve.CVE.CVEDataMeta.ID {
		aliases = append(aliases, cve.CVE.CVEDataMeta.ID)
	}

	v := Vulnerability{
		ID:      id,
		Details: cves.EnglishDescription(cve.CVE),
		Aliases: aliases,
	}

	affected := Affected{}
	affected.Package.Name = pkg
	affected.Package.Ecosystem = ecosystem

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

	for _, reference := range cve.CVE.References.ReferenceData {
		v.References = append(v.References, Reference{
			Type: "WEB",
			URL:  reference.URL,
		})
	}

	// Extract version information where we can.
	version, versionNotes := cves.ExtractVersionInfo(cve, validVersions)
	notes = append(notes, versionNotes...)

	repoToCommits := map[string][]string{}
	for _, fixCommit := range version.FixCommits {
		repoToCommits[fixCommit.Repo] = append(repoToCommits[fixCommit.Repo], fixCommit.Commit)
	}

	for repo, commits := range repoToCommits {
		gitRange := AffectedRange{
			Type: "GIT",
			Repo: repo,
		}
		for _, commit := range commits {
			gitRange.Events = append(gitRange.Events, Event{Fixed: commit})
		}
		affected.Ranges = append(affected.Ranges, gitRange)
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
	affected.Ranges = append(affected.Ranges, versionRange)
	v.Affected = append(v.Affected, affected)
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

func (v *Vulnerability) ToYAML(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	return encoder.Encode(v)
}
