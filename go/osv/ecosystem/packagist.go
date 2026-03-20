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

	"github.com/google/osv-scalibr/semantic"
)

type packagistEcosystem struct{}

var _ Enumerable = packagistEcosystem{}

func (e packagistEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.PackagistVersion]{semantic.ParsePackagistVersion(version)}, nil
}

func (e packagistEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e packagistEcosystem) IsSemver() bool {
	return false
}

func packagistAPIURL(pkg string) string {
	// Packagist API uses literal slashes for scoped packages (e.g. monolog/monolog).
	// Standard url.PathEscape will break routing because the forward slash is expected intact.
	return fmt.Sprintf("https://repo.packagist.org/p2/%s.json", pkg)
}

type packagistResponse struct {
	Packages map[string][]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

func (e packagistEcosystem) GetVersions(pkg string) ([]string, error) {
	var resp packagistResponse
	if err := fetchJSON(packagistAPIURL(pkg), &resp); err != nil {
		return nil, err
	}

	packageVersions, ok := resp.Packages[pkg]
	if !ok {
		return nil, ErrPackageNotFound
	}

	var versions []string
	// Packagist returns raw VCS branch references (like dev-master) alongside real semantic releases.
	// These are preserved and handled/sorted accordingly by sortVersions.
	for _, v := range packageVersions {
		versions = append(versions, v.Version)
	}

	return sortVersions(e, versions)
}
