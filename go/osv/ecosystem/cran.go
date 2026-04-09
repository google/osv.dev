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
	"math/big"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type cranEcosystem struct {
	p *Provider
}

var _ Enumerable = cranEcosystem{}

func cranAPIURL(pkg string) string {
	// Use the Posit Public Package Manager API to pull both the current
	// and archived versions for a specific package since CRAN doesn't
	// natively support this functionality.
	path, _ := url.JoinPath("https://packagemanager.posit.co/__api__/repos/2/packages/", url.PathEscape(pkg))
	return path
}

func (e cranEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParseCRANVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.CRANVersion]{ver}, nil
}

func (e cranEcosystem) Coarse(version string) (string, error) {
	// this logic is lifted directly from semantic.ParseCRANVersion
	// for now, treat an empty version string as valid
	if version == "" {
		version = "0"
	}

	// dashes and periods have the same weight, so we can just normalize to periods
	parts := strings.Split(strings.ReplaceAll(version, "-", "."), ".")

	comps := make([]*big.Int, 0, len(parts))

	for _, s := range parts {
		v, ok := new(big.Int).SetString(s, 10)

		if !ok {
			return "", fmt.Errorf("invalid component in version: %s", s)
		}

		comps = append(comps, v)
	}

	return coarseFromInts(bigZero, comps...), nil
}

func (e cranEcosystem) IsSemver() bool {
	return false
}

func (e cranEcosystem) GetVersions(pkg string) ([]string, error) {
	versions, err := e.p.fetchJSONPaths(cranAPIURL(pkg), "version", "archived.#.version")
	if err != nil {
		return nil, fmt.Errorf("failed to get CRAN versions for %s: %w", pkg, err)
	}

	return sortVersions(e, versions)
}
