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

type pypiEcosystem struct {
	p *Provider
}

var _ Enumerable = pypiEcosystem{}

func (e pypiEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParsePyPIVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.PyPIVersion]{ver}, nil
}

func (e pypiEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e pypiEcosystem) IsSemver() bool {
	return false
}

func pypiAPIURL(pkg string) string {
	return fmt.Sprintf("https://pypi.org/pypi/%s/json", url.PathEscape(pkg))
}

func (e pypiEcosystem) GetVersions(pkg string) ([]string, error) {
	var data struct {
		Releases map[string]any `json:"releases"`
	}
	if err := e.p.fetchJSON(pypiAPIURL(pkg), &data); err != nil {
		return nil, fmt.Errorf("failed to get PyPI versions for %s: %w", pkg, err)
	}

	versions := make([]string, 0, len(data.Releases))
	for v := range data.Releases {
		versions = append(versions, v)
	}

	return sortVersions(e, versions)
}
