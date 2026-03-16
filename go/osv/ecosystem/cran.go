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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/google/osv-scalibr/semantic"
)

type cranEcosystem struct{}

var _ Enumerable = cranEcosystem{}

// Use the Posit Public Package Manager API to pull both the current
// and archived versions for a specific package since CRAN doesn't
// natively support this functionality.
const apiPackagesURLCRAN = "https://packagemanager.posit.co/__api__/repos/2/packages/"

func (e cranEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParseCRANVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.CRANVersion]{ver}, nil
}

func (e cranEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e cranEcosystem) IsSemver() bool {
	return false
}

func (e cranEcosystem) GetVersions(pkg string) ([]string, error) {
	path, err := url.JoinPath(apiPackagesURLCRAN, url.PathEscape(pkg))
	if err != nil {
		return nil, err
	}
	resp, err := HTTPClient.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CRAN versions for %s: %s", pkg, resp.Status)
	}
	var data struct {
		Version  string `json:"version"`
		Archived []struct {
			Version string `json:"version"`
		} `json:"archived"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	var versions []string
	if data.Version != "" {
		// try parse the version
		_, err := e.Parse(data.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %s: %w", data.Version, err)
		}
		versions = append(versions, data.Version)
	}
	for _, v := range data.Archived {
		if v.Version != "" {
			// try parse the version
			_, err := e.Parse(v.Version)
			if err != nil {
				return nil, fmt.Errorf("failed to parse version %s: %w", v.Version, err)
			}
			versions = append(versions, v.Version)
		}
	}

	// sort the versions
	slices.SortFunc(versions, func(a, b string) int {
		// These should all already parse
		pa, _ := e.Parse(a)
		pb, _ := e.Parse(b)
		c, _ := pa.Compare(pb)

		return c
	})

	return versions, nil
}
