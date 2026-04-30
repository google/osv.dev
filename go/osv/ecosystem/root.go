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
	"cmp"
	"regexp"
	"strconv"
	"strings"
)

var (
	rootIOPlusRegexp    = regexp.MustCompile(`^(.+?)\+root\.io\.(\d+)$`) // <version>+root.io.<number>
	rootIOGenericRegexp = regexp.MustCompile(`^(.+?)\.root\.io\.(\d+)$`) // <version>.root.io.<number>
	rootAlpineRegexp    = regexp.MustCompile(`^(.+?)-r(\d+)$`)           // <version>-r<number>
)

type rootSubEcosystem int

const (
	rootSubEcosystemUnknown rootSubEcosystem = iota
	rootSubEcosystemAPK
	rootSubEcosystemDPKG
	rootSubEcosystemPyPI
	rootSubEcosystemNPM
	rootSubEcosystemMaven
)

type rootVersion struct {
	subEcosystem rootSubEcosystem
	delegate     Version
	patch        int
}

func (v rootVersion) Compare(other Version) (int, error) {
	otherRoot, ok := other.(rootVersion)
	if !ok {
		return 0, ErrVersionEcosystemMismatch
	}
	if c := cmp.Compare(v.subEcosystem, otherRoot.subEcosystem); c != 0 {
		// Uncertain what is best to do in the case of comparing different subecosystems.
		// We just return the comparison of the subecosystems.
		return c, nil
	}
	if c, err := v.delegate.Compare(otherRoot.delegate); err != nil || c != 0 {
		return c, err
	}

	return cmp.Compare(v.patch, otherRoot.patch), nil
}

type rootEcosystem struct {
	subEcosystem rootSubEcosystem
}

var _ Ecosystem = rootEcosystem{}

func rootEcosystemFactory(_ *Provider, suffix string) Ecosystem {
	eco, _, _ := strings.Cut(suffix, ":")
	switch strings.ToLower(eco) {
	case "alpine":
		return rootEcosystem{subEcosystem: rootSubEcosystemAPK}
	case "debian", "ubuntu":
		return rootEcosystem{subEcosystem: rootSubEcosystemDPKG}
	case "pypi", "python":
		return rootEcosystem{subEcosystem: rootSubEcosystemPyPI}
	case "npm":
		return rootEcosystem{subEcosystem: rootSubEcosystemNPM}
	case "maven":
		return rootEcosystem{subEcosystem: rootSubEcosystemMaven}
	default:
		return rootEcosystem{subEcosystem: rootSubEcosystemUnknown}
	}
}

func (e rootEcosystem) Parse(version string) (Version, error) {
	upstreamVersion := version
	rootPatch := 0
	var err error

	// Extract Root-specific suffixes
	// TODO(michaelkedar): Ported from python. Sequential checks could allow
	// rootPatch to be overwritten and suffixes not stripped.
	if m := rootIOPlusRegexp.FindStringSubmatch(version); m != nil {
		upstreamVersion = m[1]
		rootPatch, err = strconv.Atoi(m[2])
		if err != nil {
			return nil, err
		}
	}
	// Generic Format
	if m := rootIOGenericRegexp.FindStringSubmatch(version); m != nil {
		upstreamVersion = m[1]
		rootPatch, err = strconv.Atoi(m[2])
		if err != nil {
			return nil, err
		}
	}
	// Alpine Format
	if m := rootAlpineRegexp.FindStringSubmatch(upstreamVersion); m != nil {
		rootPatch, err = strconv.Atoi(m[2])
		if err != nil {
			return nil, err
		}
	}

	switch e.subEcosystem {
	case rootSubEcosystemAPK:
		ver, err := apkEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	case rootSubEcosystemDPKG:
		if upstreamVersion == "" {
			return nil, ErrVersionEcosystemMismatch
		}
		ver, err := dpkgEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}
		// logic: generic version is sufficient as delegate

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	case rootSubEcosystemPyPI:
		ver, err := pypiEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	case rootSubEcosystemNPM:
		ver, err := semverLikeEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	case rootSubEcosystemMaven:
		ver, err := mavenEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	default:
		// Unknown subecosystem, try to parse as semver-like.
		ver, err := semverLikeEcosystem{}.Parse(upstreamVersion)
		if err != nil {
			return nil, err
		}

		return rootVersion{subEcosystem: e.subEcosystem, delegate: ver, patch: rootPatch}, nil
	}
}

func (e rootEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e rootEcosystem) IsSemver() bool {
	return false
}
