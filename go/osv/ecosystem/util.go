// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
)

// fetchJSON fetches a JSON payload from the given URL and decodes it into the provided target.
// It translates HTTP 404 into ErrPackageNotFound.
func fetchJSON(urlStr string, target any) error {
	resp, err := HTTPClient.Get(urlStr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

type parsedVersion struct {
	str string
	ver Version
}

// sortVersions sorts a slice of version strings according to the ecosystem's parsing and comparison logic.
// It returns an error if any version string cannot be parsed or compared.
func sortVersions(e Ecosystem, versions []string) ([]string, error) {
	parsed := make([]parsedVersion, 0, len(versions))
	for _, v := range versions {
		p, err := e.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %s: %w", v, err)
		}
		parsed = append(parsed, parsedVersion{str: v, ver: p})
	}

	var sortErr error
	slices.SortFunc(parsed, func(a, b parsedVersion) int {
		c, err := a.ver.Compare(b.ver)
		if err != nil {
			sortErr = err
		}

		return c
	})

	result := make([]string, 0, len(parsed))
	var last string
	for i, p := range parsed {
		if i > 0 && p.str == last {
			continue
		}
		result = append(result, p.str)
		last = p.str
	}

	return result, sortErr
}

// getVersionsDepsDev enumerates versions for a package using the deps.dev API.
func getVersionsDepsDev(e Ecosystem, depsDevSystem string, pkg string) ([]string, error) {
	urlStr := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/packages/%s",
		url.PathEscape(depsDevSystem),
		url.PathEscape(pkg),
	)

	var data struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
		} `json:"versions"`
	}

	if err := fetchJSON(urlStr, &data); err != nil {
		return nil, fmt.Errorf("failed to get %s versions from deps.dev for %s: %w", depsDevSystem, pkg, err)
	}

	versions := make([]string, 0, len(data.Versions))
	for _, v := range data.Versions {
		versions = append(versions, v.VersionKey.Version)
	}

	return sortVersions(e, versions)
}
