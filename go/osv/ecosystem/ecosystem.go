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

// Package ecosystem implements version parsing and comparison for OSV ecosystems.
package ecosystem

import (
	"errors"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

var ErrCoarseNotSupported = errors.New("coarse version not supported")
var ErrVersionEcosystemMismatch = errors.New("version ecosystem mismatch")
var ErrPackageNotFound = errors.New("package not found")

type ecosystemFactory func(p *Provider, suffix string) Ecosystem

func statelessFactory[E Ecosystem](_ *Provider, _ string) Ecosystem {
	var e E
	return e
}

// debianFactory returns a factory that injects the release suffix.
func debianFactory(p *Provider, suffix string) Ecosystem {
	return debianEcosystem{release: suffix, p: p}
}

var ecosystems = map[osvconstants.Ecosystem]ecosystemFactory{
	osvconstants.EcosystemAlmaLinux:                  statelessFactory[rpmEcosystem],
	osvconstants.EcosystemAzureLinux:                 statelessFactory[rpmEcosystem],
	osvconstants.EcosystemAlpaquita:                  statelessFactory[apkEcosystem],
	osvconstants.EcosystemAlpine:                     statelessFactory[apkEcosystem],
	osvconstants.EcosystemBellSoftHardenedContainers: statelessFactory[apkEcosystem],
	osvconstants.EcosystemBioconductor:               func(p *Provider, _ string) Ecosystem { return bioconductorEcosystem{p: p} },
	osvconstants.EcosystemBitnami:                    statelessFactory[semverEcosystem],
	osvconstants.EcosystemChainguard:                 statelessFactory[apkEcosystem],
	osvconstants.EcosystemCleanStart:                 statelessFactory[apkEcosystem],
	osvconstants.EcosystemCRAN:                       func(p *Provider, _ string) Ecosystem { return cranEcosystem{p: p} },
	osvconstants.EcosystemCratesIO:                   statelessFactory[semverEcosystem],
	osvconstants.EcosystemDebian:                     debianFactory,
	osvconstants.EcosystemDockerHardenedImages:       statelessFactory[semverEcosystem],
	osvconstants.EcosystemEcho:                       echoFactory,
	osvconstants.EcosystemGHC:                        func(p *Provider, _ string) Ecosystem { return ghcEcosystem{p: p} },
	osvconstants.EcosystemGo:                         statelessFactory[semverEcosystem],
	osvconstants.EcosystemHackage:                    func(p *Provider, _ string) Ecosystem { return hackageEcosystem{p: p} },
	osvconstants.EcosystemHex:                        func(p *Provider, _ string) Ecosystem { return hexEcosystem{p: p} },
	osvconstants.EcosystemJulia:                      statelessFactory[semverEcosystem],
	osvconstants.EcosystemMageia:                     statelessFactory[rpmEcosystem],
	osvconstants.EcosystemMaven:                      func(p *Provider, _ string) Ecosystem { return mavenEcosystem{p: p} },
	osvconstants.EcosystemMinimOS:                    statelessFactory[apkEcosystem],
	osvconstants.EcosystemNPM:                        statelessFactory[semverEcosystem],
	osvconstants.EcosystemNuGet:                      func(p *Provider, _ string) Ecosystem { return nugetEcosystem{p: p} },
	osvconstants.EcosystemOpam:                       statelessFactory[opamEcosystem],
	osvconstants.EcosystemOpenEuler:                  statelessFactory[rpmEcosystem],
	osvconstants.EcosystemOpenSUSE:                   statelessFactory[rpmEcosystem],
	osvconstants.EcosystemPackagist:                  func(p *Provider, _ string) Ecosystem { return packagistEcosystem{p: p} },
	osvconstants.EcosystemPub:                        func(p *Provider, _ string) Ecosystem { return pubEcosystem{p: p} },
	osvconstants.EcosystemPyPI:                       func(p *Provider, _ string) Ecosystem { return pypiEcosystem{p: p} },
	osvconstants.EcosystemRedHat:                     statelessFactory[rpmEcosystem],
	osvconstants.EcosystemRockyLinux:                 statelessFactory[rpmEcosystem],
	osvconstants.EcosystemRoot:                       rootEcosystemFactory,
	osvconstants.EcosystemRubyGems:                   func(p *Provider, _ string) Ecosystem { return rubyGemsEcosystem{p: p} },
	osvconstants.EcosystemSUSE:                       statelessFactory[rpmEcosystem],
	osvconstants.EcosystemSwiftURL:                   statelessFactory[semverEcosystem],
	osvconstants.EcosystemUbuntu:                     statelessFactory[dpkgEcosystem],
	osvconstants.EcosystemVSCode:                     statelessFactory[semverLikeEcosystem],
	osvconstants.EcosystemWolfi:                      statelessFactory[apkEcosystem],
}

// Version is a parsed version that can be compared.
type Version interface {
	// Compare returns -1 if this version is less than other, 0 if equal, and 1 if greater.
	Compare(other Version) (int, error)
}

// SemanticVersionWrapper wraps a semantic.Version in a Version.
type SemanticVersionWrapper[V semantic.Version] struct {
	version V
}

func (v SemanticVersionWrapper[V]) Compare(other Version) (int, error) {
	otherV, ok := other.(SemanticVersionWrapper[V])
	if !ok {
		return 0, ErrVersionEcosystemMismatch
	}

	return v.version.Compare(otherV.version)
}

// Ecosystem is a version ecosystem.
type Ecosystem interface {
	// Parse parses a version string into a Version.
	// Returns an error if the version string is invalid.
	Parse(version string) (Version, error)

	// Coarse returns a version string for this ecosystem in a lexicographically
	// sortable format:
	//
	//     EE:XXXXXXXX.YYYYYYYY.ZZZZZZZZ
	//
	// where:
	//     EE is the 0-padded 2-digit epoch number (or equivalent),
	//     XXXXXXXX is the 0-padded 8-digit major version (or equivalent),
	//     YYYYYYYY is the 0-padded 8-digit minor version (or equivalent),
	//     ZZZZZZZZ is the 0-padded 8-digit patch version (or equivalent).
	//
	// The returned string is used for database range queries
	// (e.g. coarse_min <= v <= coarse_max).
	// It does not need to be a perfect representation of the version, but it
	// MUST be monotonically non-decreasing with respect to the ecosystem's sort
	// order.
	// i.e. if v1 < v2, then coarse_version(v1) <= coarse_version(v2).
	//
	// Version string '0' should map to 00:0000000.00000000.00000000
	//
	// Returns ErrCoarseNotSupported if the ecosystem does not support coarse versions.
	// Returns an error if the version string is invalid.
	Coarse(_ string) (string, error)

	// IsSemver returns true if this ecosystem uses the SEMVER version type
	// in the OSV schema (e.g. npm, Go).
	// It returns false if it uses the ECOSYSTEM type (e.g. Debian, PyPI),
	// even if it happens to use SemVer-like sorting internally (e.g. VSCode).
	IsSemver() bool
}

// Enumerable is an ecosystem that can enumerate its versions.
type Enumerable interface {
	Ecosystem

	// GetVersions enumerates known versions of a package.
	// The versions should be sorted in ascending order.
	GetVersions(_ string) ([]string, error)
}
