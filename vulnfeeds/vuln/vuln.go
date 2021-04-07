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

package vuln

import (
	"log"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
)

type AffectedRange struct {
	Type       string `json:"type" yaml:"type"`
	Repo       string `json:"repo,omitempty" yaml:"repo,omitempty"`
	Introduced string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
}

type Vulnerability struct {
	ID      string `json:"id" yaml:"id"`
	Package struct {
		Name      string `json:"name" yaml:"name"`
		Ecosystem string `json:"ecosystem" yaml:"ecosystem"`
	} `json:"package"`
	Summary  string `json:"summary" yaml:"summary"`
	Details  string `json:"details" yaml:"details"`
	Severity string `json:"severity" yaml:"severity"`
	Affects  struct {
		Ranges   []AffectedRange `json:"ranges"`
		Versions []string        `json:"versions" yaml:"versions,omitempty"`
	}
	References []string               `json:"references" yaml:"references"`
	Aliases    []string               `json:"aliases" yaml:"aliases"`
	Extra      map[string]interface{} `json:"extras,omitempty" yaml:"extra,omitempty"`
	Modified   string                 `json:"modified" yaml:"modified"`
	Created    string                 `json:"created" yaml:"created"`
}

func timestampToRFC3339(timestamp string) (string, error) {
	t, err := cves.ParseTimestamp(timestamp)
	if err != nil {
		return "", err
	}

	return t.Format(time.RFC3339), nil
}

func FromCVE(cve cves.CVEItem, pkg, ecosystem, versionType string) *Vulnerability {
	cveID := cve.CVE.CVEDataMeta.ID
	v := Vulnerability{
		ID:       "PYSEC-" + cveID,
		Summary:  "TODO",
		Details:  cves.EnglishDescription(cve.CVE),
		Severity: cve.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
		Aliases:  []string{cveID},
	}
	v.Package.Name = pkg
	v.Package.Ecosystem = "PyPI"

	var err error
	v.Created, err = timestampToRFC3339(cve.PublishedDate)
	if err != nil {
		log.Printf("Failed to parse published date: %v\n", err)
	}

	v.Modified, err = timestampToRFC3339(cve.LastModifiedDate)
	if err != nil {
		log.Printf("Failed to parse modified date: %v\n", err)
	}

	for _, reference := range cve.CVE.References.ReferenceData {
		v.References = append(v.References, reference.URL)
	}

	// Extract version information where we can.
	version := cves.ExtractVersionInfo(cve)
	for _, fixCommit := range version.FixCommits {
		v.Affects.Ranges = append(v.Affects.Ranges, AffectedRange{
			Type:  "GIT",
			Repo:  fixCommit.Repo,
			Fixed: fixCommit.Commit,
		})
	}

	for _, affected := range version.AffectedVersions {
		v.Affects.Ranges = append(v.Affects.Ranges, AffectedRange{
			Type:       versionType,
			Introduced: affected.Introduced,
			Fixed:      affected.Fixed,
		})
	}
	return &v
}
