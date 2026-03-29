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

type rubyGemsEcosystem struct{}

var _ Enumerable = rubyGemsEcosystem{}

func rubyGemsAPIURL(pkg string) string {
	return fmt.Sprintf("https://rubygems.org/api/v1/versions/%s.json", url.PathEscape(pkg))
}

func (e rubyGemsEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.RubyGemsVersion]{semantic.ParseRubyGemsVersion(version)}, nil
}

func (e rubyGemsEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e rubyGemsEcosystem) IsSemver() bool {
	return false
}

func (e rubyGemsEcosystem) GetVersions(pkg string) ([]string, error) {
	var data []struct {
		Number string `json:"number"`
	}
	if err := fetchJSON(rubyGemsAPIURL(pkg), &data); err != nil {
		return nil, fmt.Errorf("failed to get RubyGems versions for %s: %w", pkg, err)
	}
	versions := make([]string, 0, len(data))
	for _, entry := range data {
		versions = append(versions, entry.Number)
	}

	return sortVersions(e, versions)
}
