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
version_regex: ".*"
hash_all_commits: true
branch_versioning: true
file_extensions:
  - ".c"
  - ".cc"
`

func TestLoad(t *testing.T) {
	want := &RepoConfig{
		Address:          "example.com/abc",
		Name:             "abc",
		Type:             "GIT",
		BaseCPE:          "cpe",
		VersionRE:        ".*",
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
