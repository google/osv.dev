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
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type packagistEcosystem struct {
	p *Provider
}

var _ Enumerable = packagistEcosystem{}

func (e packagistEcosystem) Parse(version string) (Version, error) {
	if strings.Contains(version, "#") {
		// A quirk of packagist comparison is that to compare numbers against non-numbers, numbers are replaced with '#'
		// This means versions with a literal '#' compare equally to every number.
		// e.g. 1.0 == #.0 and 2.0 == #.0 (but 1.0 < 2.0)
		// If we allow this, we cannot guarantee an ordering of versions, so just treat any versions with # as invalid.
		// No current Packagist vulns in OSV have '#' in their versions.
		return nil, errors.New("packagist version may not contain '#'")
	}

	return SemanticVersionWrapper[semantic.PackagistVersion]{semantic.ParsePackagistVersion(version)}, nil
}

var packagistSepRegex = regexp.MustCompile(`[-_+.]`)

// Treats version as integers separated by ., -, _, or +.
// Treats 'p'/'pl' prefixes as maximal ints to ensure they sort after base versions
// (e.g. 1.0 < 1.0-p1).
func (e packagistEcosystem) Coarse(version string) (string, error) {
	if strings.Contains(version, "#") {
		return "", errors.New("packagist version may not contain '#'")
	}
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	sepParts := packagistSepRegex.Split(version, -1)

	var parts []string
	for _, sp := range sepParts {
		if sp == "" {
			parts = append(parts, "")
			continue
		}
		subParts := implicitSplitRegex.FindAllString(sp, -1)
		parts = append(parts, subParts...)
	}

	var comps []*big.Int
	count := 0
	for _, p := range parts {
		if count >= 3 {
			break
		}
		// 'p' and 'pl' (and similar) are considered greater than numbers
		if strings.HasPrefix(p, "p") {
			comps = append(comps, big.NewInt(100000000))
		} else if !isDecimal(p) || p == "" {
			break
		} else {
			bi := new(big.Int)
			bi.SetString(p, 10)
			comps = append(comps, bi)
		}
		count++
	}

	return coarseFromInts(bigZero, comps...), nil
}

func (e packagistEcosystem) IsSemver() bool {
	return false
}

func packagistAPIURL(pkg string) string {
	// Packagist API uses literal slashes for scoped packages (e.g. monolog/monolog).
	// Standard url.PathEscape will break routing because the forward slash is expected intact.
	return fmt.Sprintf("https://repo.packagist.org/p2/%s.json", pkg)
}

type packagistResponse struct {
	Packages map[string][]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

func (e packagistEcosystem) GetVersions(pkg string) ([]string, error) {
	var resp packagistResponse
	if err := e.p.fetchJSON(packagistAPIURL(pkg), &resp); err != nil {
		return nil, err
	}

	packageVersions, ok := resp.Packages[pkg]
	if !ok {
		return nil, ErrPackageNotFound
	}

	versions := make([]string, 0, len(packageVersions))
	// Packagist returns raw VCS branch references (like dev-master) alongside real semantic releases.
	// These are preserved and handled/sorted accordingly by sortVersions.
	for _, v := range packageVersions {
		versions = append(versions, v.Version)
	}

	return sortVersions(e, versions)
}
