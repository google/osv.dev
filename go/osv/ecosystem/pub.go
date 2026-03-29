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

type pubEcosystem struct{}

var _ Enumerable = pubEcosystem{}

func (e pubEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.PubVersion]{semantic.ParsePubVersion(version)}, nil
}

func (e pubEcosystem) Coarse(_ string) (string, error) {
	return "", ErrCoarseNotSupported
}

func (e pubEcosystem) IsSemver() bool {
	return false
}

func pubAPIURL(pkg string) string {
	return "https://pub.dev/api/packages/" + url.PathEscape(pkg)
}

func (e pubEcosystem) GetVersions(pkg string) ([]string, error) {
	var data struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	if err := fetchJSON(pubAPIURL(pkg), &data); err != nil {
		return nil, fmt.Errorf("failed to get Pub versions for %s: %w", pkg, err)
	}

	var versions []string
	for _, v := range data.Versions {
		if v.Version != "" {
			versions = append(versions, v.Version)
		}
	}

	return sortVersions(e, versions)
}
