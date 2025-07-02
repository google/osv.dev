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
		Type        string `json:"type"`
		Lang        string `json:"lang"`
		Description string `json:"description"`
	}
}
type ProviderMetadata struct {
	OrgID       string `json:"orgId"`
	ShortName   string `json:"shortName"`
	DateUpdated string `json:"dateUpdated"`
}

type CVE5Metadata struct {
	State             string `json:"state"`
	CVEID             CVEID  `json:"cveId"`
	AssignerOrgId     string `json:"assignerOrgId"`
	AssignerShortName string `json:"assignerShortName"`
	DateUpdated       string `json:"dateUpdated"`
	DateReserved      string `json:"dateReserved"`
	DatePublished     string `json:"datePublished"`
}

type CPE struct {
	Nodes []CPENode `json:"nodes"`
}
type CPENode struct {
	Operator string `json:"operator"`
	Negate   bool   `json:"negate"`
	CPEMatch []struct {
		Vulnerable          bool   `json:"vulnerable"`
		Criteria            string `json:"criteria"`
		VersionEndIncluding string `json:"versionEndIncluding"`
		VersionEndExcluding string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
}

type ADP struct {
	Title            string           `json:"title"`
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	ProblemTypes     ProblemTypes     `json:"problemTypes"`
	Metrics          []struct {
		CVSS CVSS `json:"cvssv3_1"`
	}
	References []Reference `json:"references"`
}
type Affected struct {
	Vendor        string     `json:"vendor"`
	Product       string     `json:"product"`
	PackageName   string     `json:"packageName"`
	CollectionUrl string     `json:"collectionURL"`
	Versions      []Versions `json:"versions"`
	Repo          string     `json:"repo"`
}

type Versions struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	LessThan        string `json:"lessThan"`
	VersionType     string `json:"versionType"`
}

type CVE5 struct {
	DataType    string       `json:"dataType"`
	DataVersion string       `json:"dataVersion"`
	Metadata    CVE5Metadata `json:"cveMetadata"`
	Containers  struct {
		CNA struct {
			ProviderMetadata ProviderMetadata `json:"providerMetadata"`
			Descriptions     []LangString     `json:"descriptions"`
			Tags             []string         `json:"tags"`
			Affected         []Affected       `json:"affected"`
			References       []Reference      `json:"references"`
			ProblemTypes     ProblemTypes     `json:"problemTypes"`
			CPEApplicability []CPE            `json:"cpeApplicability"`
		}
		ADP []ADP `json:"adp"`
	}
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

type CVSS struct {
	// VectorString corresponds to the JSON schema field "vectorString".
	VectorString string `json:"vectorString" yaml:"vectorString" mapstructure:"vectorString"`
}
