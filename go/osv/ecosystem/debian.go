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
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type debianEcosystem struct {
	dpkgEcosystem

	release string
	p       *Provider
}

var _ Enumerable = debianEcosystem{}

const debianSnapshotURL = "https://snapshot.debian.org/mr/package/%s/"
const debianFirstPackageOutputURL = "https://storage.googleapis.com/debian-osv/first_package_output/%s.json"

func (e debianEcosystem) getDebianFirstPackageVersion(pkg string) (string, error) {
	if e.release == "" {
		return "0", nil
	}
	urlStr := fmt.Sprintf(debianFirstPackageOutputURL, url.PathEscape(e.release))
	var data map[string]string
	if err := e.p.fetchJSON(urlStr, &data); err != nil {
		return "0", fmt.Errorf("failed to load release cache %s: %w", e.release, err)
	}
	if v, ok := data[pkg]; ok {
		return v, nil
	}

	return "0", nil
}

func (e debianEcosystem) GetVersions(pkg string) ([]string, error) {
	urlStr := fmt.Sprintf(debianSnapshotURL, url.PathEscape(strings.ToLower(pkg)))

	var data struct {
		Result []struct {
			Version string `json:"version"`
		} `json:"result"`
	}

	if err := e.p.fetchJSON(urlStr, &data); err != nil {
		return nil, fmt.Errorf("failed to get Debian versions for %s: %w", pkg, err)
	}

	rawVersions := make([]string, 0, len(data.Result))
	for _, r := range data.Result {
		rawVersions = append(rawVersions, r.Version)
	}

	var filtered []string
	for _, v := range rawVersions {
		// Test valid DPKG version
		if _, err := semantic.ParseDebianVersion(v); err != nil {
			continue
		}

		// Keep versions not containing +deb OR containing the specific +deb release
		if strings.Contains(v, "+deb") {
			if e.release != "" && !strings.Contains(v, "+deb"+e.release) {
				continue
			}
		}

		// Avoid duplicates gracefully, though Snapshot shouldn't have them
		if !slices.Contains(filtered, v) {
			filtered = append(filtered, v)
		}
	}

	sorted, err := sortVersions(e, filtered)
	if err != nil {
		return nil, err
	}

	firstVersion, err := e.getDebianFirstPackageVersion(pkg)
	if err != nil {
		return nil, err
	}

	if firstVersion != "0" {
		idx, _ := slices.BinarySearchFunc(sorted, firstVersion, func(a, b string) int {
			vA, _ := e.Parse(a)
			vB, _ := e.Parse(b)
			res, _ := vA.Compare(vB)

			return res
		})

		// `slices.BinarySearchFunc` returns the exact match index, or the insertion
		// index if not found. Slicing from this index onward cleanly drops all older versions.
		if idx >= 0 && idx < len(sorted) {
			sorted = sorted[idx:]
		}
	}

	return sorted, nil
}
