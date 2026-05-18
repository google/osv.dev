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
	"strconv"
	"strings"

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

// https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
// Capture epoch, and remainder, since that's all we need to actually parse
var pypiCanonicalRegex = regexp.MustCompile(`^\s*v?(?:(?:([0-9]+)!)?((?:[0-9]+(?:\.[0-9]+)*)(?:[-_\.]?(?:(?:a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?:[0-9]+)?)?(?:(?:-(?:[0-9]+))|(?:[-_\.]?(?:post|rev|r)[-_\.]?(?:[0-9]+)?))?(?:[-_\.]?(?:dev)[-_\.]?(?:[0-9]+)?)?)(?:\+(?:[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?)\s*$`)

var pypiCoarseVersioner = CoarseVersioner{
	Separators:    regexp.MustCompile(`[.]`),
	Truncate:      regexp.MustCompile(`[+_-]`),
	ImplicitSplit: true,
	EmptyAs:       nil,
}

func (e pypiEcosystem) Coarse(version string) (string, error) {
	version = strings.ToLower(version)
	match := pypiCanonicalRegex.FindStringSubmatch(version)
	if match == nil {
		// no match, this is a legacy version which sorts before non-legacy
		return "00:00000000.00000000.00000000", nil
	}
	epochStr := match[1]
	epochlessVer := match[2]
	epochStr = strings.TrimLeft(epochStr, "0")
	if epochStr == "" {
		epochStr = "0"
	}
	if len(epochStr) > 2 {
		// epoch is > 99, return maximum coarse version
		return "99:99999999.99999999.99999999", nil
	}
	epoch, err := strconv.Atoi(epochStr)
	if err != nil {
		// we've validated the string, so this should be unreachable
		return "", err
	}

	return pypiCoarseVersioner.Format(epoch, epochlessVer), nil
}

func (e pypiEcosystem) IsSemver() bool {
	return false
}

func pypiAPIURL(pkg string) string {
	return fmt.Sprintf("https://pypi.org/pypi/%s/json", url.PathEscape(pkg))
}

func (e pypiEcosystem) GetVersions(pkg string) ([]string, error) {
	versions, err := e.p.fetchJSONPaths(pypiAPIURL(pkg), "releases.@keys")
	if err != nil {
		return nil, fmt.Errorf("failed to get PyPI versions for %s: %w", pkg, err)
	}

	return sortVersions(e, versions)
}

var pypiNormalizeRegex = regexp.MustCompile(`[-_.]+`)

func (e pypiEcosystem) NormalizePackageName(name string) string {
	return strings.ToLower(pypiNormalizeRegex.ReplaceAllString(name, "-"))
}

var _ PackageNameNormalizer = pypiEcosystem{}
