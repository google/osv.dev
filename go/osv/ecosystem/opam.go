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
	"fmt"
	"strings"
)

type opamEcosystem struct {
	dpkgEcosystem
}

var _ Ecosystem = opamEcosystem{}

// Opam disables the Enumerable ecosystem interface as the record is pre-enumerated on import.
type githubContent struct {
	Name string `json:"name"`
}

func (e opamEcosystem) getVersions(pkg string) ([]string, error) {
	url1 := fmt.Sprintf("https://api.github.com/repos/ocaml/opam-repository/contents/packages/%s", pkg)
	url2 := fmt.Sprintf("https://api.github.com/repos/ocaml/opam-repository-archive/contents/packages/%s", pkg)

	var list1, list2 []githubContent
	err1 := fetchJSON(url1, &list1)
	err2 := fetchJSON(url2, &list2)

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

	for _, item := range list1 {
		if strings.HasPrefix(item.Name, prefix) {
			v := strings.TrimPrefix(item.Name, prefix)
			if !seen[v] {
				versions = append(versions, v)
				seen[v] = true
			}
		}
	}
	for _, item := range list2 {
		if strings.HasPrefix(item.Name, prefix) {
			v := strings.TrimPrefix(item.Name, prefix)
			if !seen[v] {
				versions = append(versions, v)
				seen[v] = true
			}
		}
	}

	return sortVersions(e, versions)
}

