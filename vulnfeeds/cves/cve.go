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
	CVETimeFormat  = "2006-01-02T15:04Z07:00"
	CVE5TimeFormat = "2006-01-02T00:00:00"
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

type CVEImpact struct {
	BaseMetricV3 struct {
		CVSSV3 struct {
			VectorString string `json:"vectorString"`
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssV3"`
	} `json:"baseMetricV3"`
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
	Impact           CVEImpact `json:"impact"`
	PublishedDate    string    `json:"publishedDate"`
	LastModifiedDate string    `json:"lastModifiedDate"`
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

func ParseCVE5Timestamp(timestamp string) (time.Time, error) {
	return time.Parse(CVE5TimeFormat, timestamp)
}
