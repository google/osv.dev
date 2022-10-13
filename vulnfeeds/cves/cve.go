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
	"encoding/json"
	"io"
	"time"
)

const (
	CVETimeFormat = "2006-01-02T15:04Z07:00"
)

type CVE struct {
	CVEDataMeta struct {
		ID string
	} `json:"CVE_data_meta"`
	References  CVEReferences `json:"references"`
	Description struct {
		DescriptionData []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description_data"`
	} `json:"description"`
}
type CVEReferenceData struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	RefSource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type CVEReferences struct {
	ReferenceData []CVEReferenceData `json:"reference_data"`
}

type CVEItem struct {
	CVE            CVE `json:"cve"`
	Configurations struct {
		Nodes []struct {
			Operator string `json:"operator"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				CPE23URI              string `json:"cpe23Uri"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 struct {
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssV3"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

type NVDCVE struct {
	CVEItems         []CVEItem `json:"CVE_Items"`
	CVEDataTimestamp string    `json:"CVE_data_timestamp"`
}

type NVDCVE2 struct {
	ResultsPerPage  *int              `json:"ResultsPerPage"`
	StartIndex      *int              `json:"StartIndex"`
	TotalResults    *int              `json:"TotalResults"`
	Format          *string           `json:"format"`
	Version         *string           `json:"version"`
	Timestamp       *string           `json:"timestamp"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

func (n *NVDCVE2) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(n)
}

func EnglishDescription(cve CVE) string {
	for _, desc := range cve.Description.DescriptionData {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func ParseTimestamp(timestamp string) (time.Time, error) {
	return time.Parse(CVETimeFormat, timestamp)
}
