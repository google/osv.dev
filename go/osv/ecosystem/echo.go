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
	"regexp"
	"strconv"
	"strings"
)

// echoEcosystem is the Echo container security ecosystem.
//
// Echo provides secured packages across multiple ecosystems:
//   - Echo        - Debian-based packages (dpkg versioning)
//   - Echo:PyPI   - Python packages (PyPI/PEP 440 versioning)
//   - Echo:Maven  - Maven packages (Maven versioning)
//   - Echo:npm    - npm packages (SemVer versioning, +echo.N aware)
//
// Versioning is delegated to the underlying ecosystem helper.
type echoEcosystem struct {
	Ecosystem
}

func echoFactory(p *Provider, suffix string) Ecosystem {
	switch {
	case strings.EqualFold(suffix, "pypi"):
		return echoEcosystem{Ecosystem: pypiEcosystem{p: p}}
	case strings.EqualFold(suffix, "maven"):
		return echoEcosystem{Ecosystem: mavenEcosystem{p: p}}
	case strings.EqualFold(suffix, "npm"):
		return echoEcosystem{Ecosystem: echoSemverEcosystem{}}
	default:
		return echoEcosystem{Ecosystem: dpkgEcosystem{}}
	}
}

// echoBuildRe matches Echo's `+echo.N` build suffix.
var echoBuildRe = regexp.MustCompile(`\+echo\.(\d+)`)

// echoBuildNumber returns the `+echo.N` build number (0 if there is none).
func echoBuildNumber(version string) int {
	m := echoBuildRe.FindStringSubmatch(version)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}

	return n
}

// echoSemverEcosystem orders Echo:npm packages. npm uses SemVer, which
// excludes build metadata from precedence, so Echo's `+echo.N` builds would
// otherwise compare equal to the base version and to each other. PyPI and
// Maven order `+echo.N` natively (local versions / qualifiers); npm does not,
// so we tie-break on the echo build number to keep
// `1.2.3 < 1.2.3+echo.1 < 1.2.3+echo.2 < 1.2.4`.
//
// It embeds semverLikeEcosystem (the ECOSYSTEM version type), matching how
// Echo advisories express their ranges.
type echoSemverEcosystem struct {
	semverLikeEcosystem
}

func (e echoSemverEcosystem) Parse(version string) (Version, error) {
	inner, err := e.semverLikeEcosystem.Parse(version)
	if err != nil {
		return nil, err
	}

	return echoSemverVersion{inner: inner, build: echoBuildNumber(version)}, nil
}

// echoSemverVersion is a SemVer version paired with its `+echo.N` build number.
type echoSemverVersion struct {
	inner Version
	build int
}

var _ Version = echoSemverVersion{}

func (v echoSemverVersion) Compare(other Version) (int, error) {
	otherV, ok := other.(echoSemverVersion)
	if !ok {
		return 0, ErrVersionEcosystemMismatch
	}

	// SemVer precedence first (build metadata is ignored there); if equal,
	// tie-break on the echo build number.
	if c, err := v.inner.Compare(otherV.inner); err != nil || c != 0 {
		return c, err
	}

	switch {
	case v.build < otherV.build:
		return -1, nil
	case v.build > otherV.build:
		return 1, nil
	default:
		return 0, nil
	}
}

func (e echoEcosystem) NormalizePackageName(name string) string {
	// We want to apply the normalization of the inner ecosystem.
	if norm, ok := e.Ecosystem.(PackageNameNormalizer); ok {
		return norm.NormalizePackageName(name)
	}

	return name
}

var _ PackageNameNormalizer = echoEcosystem{}
