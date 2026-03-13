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

// dpkgEcosystem is an ecosystem for ecosystems using Debian Package versioning.
type dpkgEcosystem struct{}

var _ Ecosystem = dpkgEcosystem{}

func (e dpkgEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParseDebianVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.DebianVersion]{ver}, nil
}

func (e dpkgEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e dpkgEcosystem) IsSemver() bool {
	return false
}
