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
	CVE5TimeFormat = "2006-01-02T15:04:05"
)

type NVDCVE2 struct {
	ResultsPerPage  *int              `json:"resultsPerPage"`
	StartIndex      *int              `json:"startIndex"`
	TotalResults    *int              `json:"totalResults"`
	Format          *string           `json:"format"`
	Version         *string           `json:"version"`
	Timestamp       *string           `json:"timestamp"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

func (n *NVDCVE2) ToJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(n)
}

type CVE5 struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Metadata    struct {
		State             string `json:"state"`
		ID                string `json:"cveId"`
		AssignerOrgId     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		DateUpdated       string `json:"dateUpdated"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
	}
	Containers struct {
		CNA struct {
			ProviderMetadata struct {
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			}
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}
			Tags     []string `json:"tags"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				}
			}
			References []struct {
				URL string `json:"url"`
			}
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
				}
			}
		}
	}
}

func EnglishDescription(cve CVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func ParseCVE5Timestamp(timestamp string) (time.Time, error) {
	return time.Parse(CVE5TimeFormat, timestamp)
}

type CVSS struct {
	// VectorString corresponds to the JSON schema field "vectorString".
	VectorString string `json:"vectorString" yaml:"vectorString" mapstructure:"vectorString"`
}
