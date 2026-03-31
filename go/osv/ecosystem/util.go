// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecosystem

import (
	"fmt"
	"slices"
)

type parsedVersion struct {
	str string
	ver Version
}

// sortVersions sorts a slice of version strings according to the ecosystem's parsing and comparison logic.
// It returns an error if any version string cannot be parsed or compared.
func sortVersions(e Ecosystem, versions []string) ([]string, error) {
	parsed := make([]parsedVersion, 0, len(versions))
	for _, v := range versions {
		p, err := e.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %s: %w", v, err)
		}
		parsed = append(parsed, parsedVersion{str: v, ver: p})
	}

	var sortErr error
	slices.SortFunc(parsed, func(a, b parsedVersion) int {
		c, err := a.ver.Compare(b.ver)
		if err != nil {
			sortErr = err
		}

		return c
	})

	result := make([]string, 0, len(parsed))
	var last string
	for i, p := range parsed {
		if i > 0 && p.str == last {
			continue
		}
		result = append(result, p.str)
		last = p.str
	}

	return result, sortErr
}
