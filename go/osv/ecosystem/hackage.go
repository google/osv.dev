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
	"net/url"

	"github.com/google/osv-scalibr/semantic"
)

type hackageEcosystem struct {
	p *Provider
}

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

func hackageAPIURL(pkg string) string {
	return fmt.Sprintf("https://hackage.haskell.org/package/%s.json", url.PathEscape(pkg))
}

func (e hackageEcosystem) GetVersions(pkg string) ([]string, error) {
	var data map[string]any
	if err := e.p.fetchJSON(hackageAPIURL(pkg), &data); err != nil {
		return nil, fmt.Errorf("failed to get Hackage versions for %s: %w", pkg, err)
	}

	versions := make([]string, 0, len(data))
	for v := range data {
		versions = append(versions, v)
	}

	return sortVersions(e, versions)
}
