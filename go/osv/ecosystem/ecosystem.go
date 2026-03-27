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
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

var ErrCoarseNotSupported = errors.New("coarse version not supported")
var ErrVersionEcosystemMismatch = errors.New("version ecosystem mismatch")
var ErrPackageNotFound = errors.New("package not found")

// HTTPClient is the global HTTP client used by ecosystems for fetching
// version information and other external data. It may be overridden for testing.
var HTTPClient = http.DefaultClient

// Get returns an ecosystem for the given ecosystem name.
// If the ecosystem is not found, it returns nil, false.
//
// The ecosystem name can optionally include a version suffix (e.g. "Debian:10").
func Get(ecosystem string) (Ecosystem, bool) {
	name, suffix, _ := strings.Cut(ecosystem, ":")
	f, ok := ecosystems[osvconstants.Ecosystem(name)]
	if !ok {
		return nil, false
	}
	// Wrap the ecosystem to handle "0" versions.
	e := f(suffix)
	if enum, ok := e.(Enumerable); ok {
		return &enumerableWrapper{Enumerable: enum}, true
	}

	return &ecosystemWrapper{Ecosystem: e}, true
}

type ecosystemFactory func(suffix string) Ecosystem

// statelessFactory returns a factory for the given ecosystem type that ignores the suffix
// and returns the zero value of E.
func statelessFactory[E Ecosystem](_ string) Ecosystem {
	var e E
	return e
}

// debianFactory returns a factory that injects the release suffix.
func debianFactory(suffix string) Ecosystem {
	return debianEcosystem{release: suffix}
}

var ecosystems = map[osvconstants.Ecosystem]ecosystemFactory{
	osvconstants.EcosystemAlmaLinux:                  statelessFactory[rpmEcosystem],
	osvconstants.EcosystemAlpaquita:                  statelessFactory[apkEcosystem],
	osvconstants.EcosystemAlpine:                     statelessFactory[apkEcosystem],
	osvconstants.EcosystemBellSoftHardenedContainers: statelessFactory[apkEcosystem],
	osvconstants.EcosystemBioconductor:               statelessFactory[bioconductorEcosystem],
	osvconstants.EcosystemBitnami:                    statelessFactory[semverEcosystem],
	osvconstants.EcosystemChainguard:                 statelessFactory[apkEcosystem],
	osvconstants.EcosystemCleanStart:                 statelessFactory[apkEcosystem],
	osvconstants.EcosystemCRAN:                       statelessFactory[cranEcosystem],
	osvconstants.EcosystemCratesIO:                   statelessFactory[semverEcosystem],
	osvconstants.EcosystemDebian:                     debianFactory,
	osvconstants.EcosystemDockerHardenedImages:       statelessFactory[semverEcosystem],
	osvconstants.EcosystemEcho:                       statelessFactory[dpkgEcosystem],
	osvconstants.EcosystemGHC:                        statelessFactory[ghcEcosystem],
	osvconstants.EcosystemGo:                         statelessFactory[semverEcosystem],
	osvconstants.EcosystemHackage:                    statelessFactory[hackageEcosystem],
	osvconstants.EcosystemHex:                        statelessFactory[hexEcosystem],
	osvconstants.EcosystemJulia:                      statelessFactory[semverEcosystem],
	osvconstants.EcosystemMageia:                     statelessFactory[rpmEcosystem],
	osvconstants.EcosystemMaven:                      statelessFactory[mavenEcosystem],
	osvconstants.EcosystemMinimOS:                    statelessFactory[apkEcosystem],
	osvconstants.EcosystemNPM:                        statelessFactory[semverEcosystem],
	osvconstants.EcosystemNuGet:                      statelessFactory[nugetEcosystem],
	osvconstants.EcosystemOpam:                       statelessFactory[opamEcosystem],
	osvconstants.EcosystemOpenEuler:                  statelessFactory[rpmEcosystem],
	osvconstants.EcosystemOpenSUSE:                   statelessFactory[rpmEcosystem],
	osvconstants.EcosystemPackagist:                  statelessFactory[packagistEcosystem],
	osvconstants.EcosystemPub:                        statelessFactory[pubEcosystem],
	osvconstants.EcosystemPyPI:                       statelessFactory[pyPIEcosystem],
	osvconstants.EcosystemRedHat:                     statelessFactory[rpmEcosystem],
	osvconstants.EcosystemRockyLinux:                 statelessFactory[rpmEcosystem],
	osvconstants.EcosystemRoot:                       rootEcosystemFactory,
	osvconstants.EcosystemRubyGems:                   statelessFactory[rubyGemsEcosystem],
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
