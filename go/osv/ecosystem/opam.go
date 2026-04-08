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
	"errors"
	"strings"
)

type opamEcosystem struct {
	dpkgEcosystem

	p *Provider
}

var _ Ecosystem = opamEcosystem{}

// Opam disables the Enumerable ecosystem interface as the record is pre-enumerated on import.
// var _ Enumerable = opamEcosystem{}
func (e opamEcosystem) getVersions(pkg string) ([]string, error) {
	// TODO(michaelkedar): these unauthenticated GitHub API requests have a rate limit of 60/hr.
	// If we enable this, we'd probably want to add some auth key to our workers.
	url1 := "https://api.github.com/repos/ocaml/opam-repository/contents/packages/" + pkg
	url2 := "https://api.github.com/repos/ocaml/opam-repository-archive/contents/packages/" + pkg

	list1, err1 := e.p.fetchJSONPaths(url1, "#.name")
	list2, err2 := e.p.fetchJSONPaths(url2, "#.name")

	if errors.Is(err1, ErrPackageNotFound) && errors.Is(err2, ErrPackageNotFound) {
		return nil, ErrPackageNotFound
	}

	if err1 != nil && !errors.Is(err1, ErrPackageNotFound) {
		return nil, err1
	}
	if err2 != nil && !errors.Is(err2, ErrPackageNotFound) {
		return nil, err2
	}

	var versions []string
	prefix := pkg + "."
	seen := make(map[string]bool)

	for _, name := range list1 {
		if strings.HasPrefix(name, prefix) {
			v := strings.TrimPrefix(name, prefix)
			if !seen[v] {
				versions = append(versions, v)
				seen[v] = true
			}
		}
	}
	for _, name := range list2 {
		if strings.HasPrefix(name, prefix) {
			v := strings.TrimPrefix(name, prefix)
			if !seen[v] {
				versions = append(versions, v)
				seen[v] = true
			}
		}
	}

	return sortVersions(e, versions)
}
