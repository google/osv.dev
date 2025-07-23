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

package cves

import (
	"strings"
	"time"
)

const (
	CVE5TimeFormat = "2006-01-02T15:04:05"
)

type ProblemTypes []struct {
	Descriptions []struct {
		Type        string `json:"type,omitempty"`
		Lang        string `json:"lang,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"descriptions,omitempty"`
}
type ProviderMetadata struct {
	OrgID       string `json:"orgId,omitempty"`
	ShortName   string `json:"shortName,omitempty"`
	DateUpdated string `json:"dateUpdated,omitempty"`
}

type CVE5Metadata struct {
	State             string `json:"state,omitempty"`
	CVEID             CVEID  `json:"cveId,omitempty"`
	AssignerOrgId     string `json:"assignerOrgId,omitempty"`
	AssignerShortName string `json:"assignerShortName,omitempty"`
	DateUpdated       string `json:"dateUpdated,omitempty"`
	DateReserved      string `json:"dateReserved,omitempty"`
	DatePublished     string `json:"datePublished,omitempty"`
}

type CPE struct {
	Nodes []CPENode `json:"nodes,omitempty"`
}
type CPENode struct {
	Operator string `json:"operator,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	CPEMatch []struct {
		Vulnerable          bool   `json:"vulnerable,omitempty"`
		Criteria            string `json:"criteria,omitempty"`
		VersionEndIncluding string `json:"versionEndIncluding,omitempty"`
		VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
	} `json:"cpeMatch,omitempty"`
}

type Impact struct {
	CAPECID      string       `json:"capecId,omitempty"`
	Descriptions []LangString `json:"descriptions,omitempty"`
}

type BaseCVSS struct {
	Version      string  `json:"version,omitempty"`
	VectorString string  `json:"vectorString,omitempty"`
	BaseScore    float64 `json:"baseScore,omitempty"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}

type CVSS struct {
	// VectorString corresponds to the JSON schema field "vectorString".
	VectorString string `json:"vectorString,omitempty" yaml:"vectorString" mapstructure:"vectorString"`
}

type Metrics struct {
	Format    string       `json:"format,omitempty"`
	Scenarios []LangString `json:"scenarios,omitempty"`
	CVSSV4_0  BaseCVSS     `json:"cvssv4_0,omitempty"`
	CVSSV3_1  BaseCVSS     `json:"cvssv3_1,omitempty"`
	CVSSV3_0  BaseCVSS     `json:"cvssv3_0,omitempty"`
	CVSSV2_0  BaseCVSS     `json:"cvssv2_0,omitempty"`
	Other     struct {
		Type    string `json:"type,omitempty"`
		Content any    `json:"content,omitempty"`
	} `json:"other,omitempty"`
}

type CNA struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"` // Required
	Descriptions     []LangString     `json:"descriptions"`     // Required
	Affected         []Affected       `json:"affected"`         // Required
	ProblemTypes     ProblemTypes     `json:"problemTypes,omitempty"`
	References       []Reference      `json:"references"` //Required
	Impacts          []Impact         `json:"impacts,omitempty"`
	Metrics          []Metrics        `json:"metrics,omitempty"`
	Tags             []string         `json:"tags,omitempty"`
	CPEApplicability []CPE            `json:"cpeApplicability,omitempty"`
	DateAssigned     string           `json:"dateAssigned,omitempty"`
	DatePublic       string           `json:"datePublic,omitempty"`
	Title            string           `json:"title,omitempty"`
}

type ADP struct {
	Title            string           `json:"title,omitempty"`
	ProviderMetadata ProviderMetadata `json:"providerMetadata,omitempty"`
	ProblemTypes     ProblemTypes     `json:"problemTypes,omitempty"`
	Metrics          []Metrics        `json:"metrics,omitempty"`
	References       []Reference      `json:"references,omitempty"`
}
type Affected struct {
	Vendor        string     `json:"vendor,omitempty"`
	Product       string     `json:"product,omitempty"`
	PackageName   string     `json:"packageName,omitempty"`
	CollectionUrl string     `json:"collectionURL,omitempty"`
	Versions      []Versions `json:"versions,omitempty"`
	Repo          string     `json:"repo,omitempty"`
}

type Versions struct {
	Version         string `json:"version,omitempty"`
	Status          string `json:"status,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
	LessThan        string `json:"lessThan,omitempty"`
	VersionType     string `json:"versionType,omitempty"`
}

type CVE5 struct {
	DataType    string       `json:"dataType,omitempty"`
	DataVersion string       `json:"dataVersion,omitempty"`
	Metadata    CVE5Metadata `json:"cveMetadata,omitempty"`
	Containers  struct {
		CNA CNA   `json:"cna"`
		ADP []CNA `json:"adp,omitempty"`
	} `json:"containers,omitempty"`
}

func EnglishDescription(descriptions []LangString) string {
	for _, desc := range descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func ParseCVE5Timestamp(timestamp string) (time.Time, error) {
	if strings.HasSuffix(timestamp, "Z") {
		timestamp = timestamp[:len(timestamp)-1]
	}
	return time.Parse(CVE5TimeFormat, timestamp)
}
