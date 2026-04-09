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
	"regexp"

	"github.com/google/osv-scalibr/semantic"
)

type rubyGemsEcosystem struct {
	p *Provider
}

var _ Enumerable = rubyGemsEcosystem{}

func rubyGemsAPIURL(pkg string) string {
	return fmt.Sprintf("https://rubygems.org/api/v1/versions/%s.json", url.PathEscape(pkg))
}

func (e rubyGemsEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.RubyGemsVersion]{semantic.ParseRubyGemsVersion(version)}, nil
}

var rubyGemsCoarseVersioner = CoarseVersioner{
	Separators:    regexp.MustCompile(`[.]`),
	Truncate:      regexp.MustCompile(`-`),
	ImplicitSplit: true,
	EmptyAs:       &[]string{""}[0],
}

func (e rubyGemsEcosystem) Coarse(version string) (string, error) {
	return rubyGemsCoarseVersioner.Format(0, version), nil
}

func (e rubyGemsEcosystem) IsSemver() bool {
	return false
}

func (e rubyGemsEcosystem) GetVersions(pkg string) ([]string, error) {
	versions, err := e.p.fetchJSONPaths(rubyGemsAPIURL(pkg), "#.number")
	if err != nil {
		return nil, fmt.Errorf("failed to get RubyGems versions for %s: %w", pkg, err)
	}

	return sortVersions(e, versions)
}
