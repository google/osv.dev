/*
Copyright 2022 Google LLC

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

const cfg = `
address: "example.com/abc"
name: "abc"
type: "GIT"
base_cpe: "cpe"
hash_all_commits: true
branch_versioning: true
file_extensions:
  - ".c"
  - ".cc"
`

func TestParseConfig(t *testing.T) {
	want := &RepoConfig{
		Address:          "example.com/abc",
		Name:             "abc",
		Type:             "GIT",
		BaseCPE:          "cpe",
		HashAllCommits:   true,
		BranchVersioning: true,
		FileExts:         []string{".c", ".cc"},
	}

	got, err := parseConfig([]byte(cfg))
	if err != nil {
		t.Errorf("parseConfig() returned an unexpected error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("parseConfig() returned an unexpected diff (-want, +got):\n%s", diff)
	}
}
