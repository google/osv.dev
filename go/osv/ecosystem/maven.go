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
	"regexp"

	"github.com/google/osv-scalibr/semantic"
)

type mavenEcosystem struct {
	p *Provider
}

var _ Enumerable = mavenEcosystem{}

func (e mavenEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.MavenVersion]{semantic.ParseMavenVersion(version)}, nil
}

var mavenCoarseVersioner = CoarseVersioner{
	Separators:    regexp.MustCompile(`[.]`),
	Truncate:      regexp.MustCompile(`-`),
	ImplicitSplit: true,
	EmptyAs:       &[]string{"0"}[0],
}

func (e mavenEcosystem) Coarse(version string) (string, error) {
	return mavenCoarseVersioner.Format(0, version), nil
}

func (e mavenEcosystem) IsSemver() bool {
	return false
}

func (e mavenEcosystem) GetVersions(pkg string) ([]string, error) {
	return e.p.getVersionsDepsDev(e, "maven", pkg)
}
