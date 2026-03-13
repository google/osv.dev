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

import "github.com/google/osv-scalibr/semantic"

type hackageEcosystem struct{}

var _ Enumerable = hackageEcosystem{}

func (e hackageEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParseHackageVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.HackageVersion]{ver}, nil
}

func (e hackageEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e hackageEcosystem) IsSemver() bool {
	return false
}
func (e hackageEcosystem) GetVersions(_ string) ([]string, error) {
	panic("not yet implemented")
}
