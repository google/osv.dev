// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecosystem

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type nugetEcosystem struct{}

var _ Enumerable = nugetEcosystem{}

// Parse parses a NuGet version.
// NuGet versioning departure from strict SemVer (per Microsoft docs):
//   - Optional 4th component (x.y.z.R).
//   - Prerelease components are compared case insensitively.
//   - Non-major version segments are optional (e.g. "1" is valid).
func (e nugetEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.NuGetVersion]{semantic.ParseNuGetVersion(version)}, nil
}

func (e nugetEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e nugetEcosystem) IsSemver() bool {
	return false
}

func nugetAPIURL(pkg string) string {
	return fmt.Sprintf("https://api.nuget.org/v3/registration5-semver1/%s/index.json", url.PathEscape(strings.ToLower(pkg)))
}

type nugetResponse struct {
	Items []struct {
		Items []struct {
			CatalogEntry struct {
				Version string `json:"version"`
			} `json:"catalogEntry"`
		} `json:"items"`
		ID string `json:"@id"`
	} `json:"items"`
}

type nugetPage struct {
	Items []struct {
		CatalogEntry struct {
			Version string `json:"version"`
		} `json:"catalogEntry"`
	} `json:"items"`
}

func (e nugetEcosystem) GetVersions(pkg string) ([]string, error) {
	var resp nugetResponse
	if err := fetchJSON(nugetAPIURL(pkg), &resp); err != nil {
		return nil, err
	}

	var versions []string
	for _, page := range resp.Items {
		if len(page.Items) > 0 {
			for _, item := range page.Items {
				versions = append(versions, item.CatalogEntry.Version)
			}
		} else {
			var nested nugetPage
			if err := fetchJSON(page.ID, &nested); err != nil {
				return nil, err
			}
			for _, item := range nested.Items {
				versions = append(versions, item.CatalogEntry.Version)
			}
		}
	}

	return sortVersions(e, versions)
}

