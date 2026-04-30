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
	"errors"
	"fmt"
	"net/url"
)

type bioconductorEcosystem struct {
	semverLikeEcosystem

	p *Provider
}

var _ Ecosystem = bioconductorEcosystem{}

// FIXME(michaelkedar): Newer releases (3.22+) of bioconductor seem to be returning 500s for package queries.
// 500 seems to be the response when the bioc_version is invalid (i.e. it's also 500 if bioc_version is e.g. 12.3).
// I am guessing the API has changed or is broken for newer bioc versions.
//
// OSV.dev currently has zero Bioconductor packages, so I'm not going to spend time debugging this.
// Removing the Enumerable interface for now (but keeping the code for reference).
// var _ Enumerable = bioconductorEcosystem{}

func apiPackageURLPositBioconductor(pkg, biocVersion string) string {
	// Use the Posit Public Package Manager API to pull both the current and
	// older versions for a specific package since Bioconductor doesn't natively
	// support this functionality.
	return fmt.Sprintf("https://packagemanager.posit.co/__api__/repos/4/packages/%s?bioc_version=%s",
		url.PathEscape(pkg),
		url.QueryEscape(biocVersion),
	)
}

const apiBiocVersionsURL = "https://packagemanager.posit.co/__api__/status"

func (e bioconductorEcosystem) getVersions(pkg string) ([]string, error) {
	biocVersions, err := e.getBiocVersions()
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, biocVersion := range biocVersions {
		res, err := e.p.fetchJSONPaths(apiPackageURLPositBioconductor(pkg, biocVersion), "version")
		if err != nil {
			if errors.Is(err, ErrPackageNotFound) {
				continue
			}

			return nil, fmt.Errorf("failed to get Bioconductor versions for %s: %w", pkg, err)
		}
		if len(res) > 0 && res[0] != "" {
			versions = append(versions, res[0])
		}
	}

	if len(versions) == 0 {
		return nil, ErrPackageNotFound
	}

	return sortVersions(e, versions)
}

func (e bioconductorEcosystem) getBiocVersions() ([]string, error) {
	versions, err := e.p.fetchJSONPaths(apiBiocVersionsURL, "bioc_versions.#.bioc_version")
	if err != nil {
		return nil, fmt.Errorf("failed to get Bioconductor versions: %w", err)
	}

	return versions, nil
}
