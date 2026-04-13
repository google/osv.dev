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

import "github.com/google/osv-scalibr/semantic"

// semverLikeEcosystem is an ecosystem that uses a SemVer-like versions in the OSV schema.
// but uses the ECOSYSTEM version type in the OSV schema.
type semverLikeEcosystem struct{}

var _ Ecosystem = semverLikeEcosystem{}

func (e semverLikeEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.SemverVersion]{semantic.ParseSemverVersion(version)}, nil
}

func (e semverLikeEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e semverLikeEcosystem) IsSemver() bool {
	return false
}

// semverEcosystem is an ecosystem for the SEMVER version type in the OSV schema.
type semverEcosystem struct {
	semverLikeEcosystem
}

var _ Ecosystem = semverEcosystem{}

func (e semverEcosystem) IsSemver() bool {
	return true
}
