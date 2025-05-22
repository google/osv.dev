package common

import (
	"cmp"
	"reflect"
	"strings"
)

type AffectedCommit struct {
	Repo         string `json:"repo,omitempty" yaml:"repo,omitempty"`
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Limit        string `json:"limit,omitempty" yaml:"limit,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

func (ac *AffectedCommit) SetRepo(repo string) {
	// GitHub.com repos are demonstrably case-insensitive, and frequently
	// expressed in URLs with varying cases, so normalize them to lowercase.
	// vulns.AddPkgInfo() treats repos case sensitively, and this can result in
	// incorrect behaviour.
	if strings.Contains(strings.ToLower(repo), "github.com") {
		repo = strings.ToLower(repo)
	}
	ac.Repo = repo
}

func (ac *AffectedCommit) SetIntroduced(commit string) {
	ac.Introduced = commit
}

func (ac *AffectedCommit) SetFixed(commit string) {
	ac.Fixed = commit
}

func (ac *AffectedCommit) SetLimit(commit string) {
	ac.Limit = commit
}

func (ac *AffectedCommit) SetLastAffected(commit string) {
	ac.LastAffected = commit
}

// Check if the commit range actually spans any commits.
// A range that starts and ends with the same commit is not considered a valid range.
func (ac *AffectedCommit) InvalidRange() bool {
	if ac.Introduced == ac.Fixed && ac.Introduced != "" {
		return true
	}
	if ac.Introduced == ac.LastAffected && ac.Introduced != "" {
		return true
	}
	return false
}

// Helper function for sorting AffectedCommit for stability.
// Sorts by Repo, then Fixed, then LastAffected, then Introduced.
func AffectedCommitCompare(i, j AffectedCommit) int {
	if n := cmp.Compare(i.Repo, j.Repo); n != 0 {
		return n
	}
	if n := cmp.Compare(i.Fixed, j.Fixed); n != 0 {
		return n
	}
	if n := cmp.Compare(i.LastAffected, j.LastAffected); n != 0 {
		return n
	}
	return cmp.Compare(i.Introduced, j.Introduced)
}

type AffectedVersion struct {
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

// Synthetic enum of supported commit types.
type CommitType int

const (
	Introduced CommitType = iota
	Fixed
	Limit
	LastAffected
)

type VersionInfo struct {
	AffectedCommits  []AffectedCommit  `json:"affect_commits,omitempty" yaml:"affected_commits,omitempty"`
	AffectedVersions []AffectedVersion `json:"affected_versions,omitempty" yaml:"affected_versions,omitempty"`
}

func (vi *VersionInfo) HasFixedVersions() bool {
	for _, av := range vi.AffectedVersions {
		if av.Fixed != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasLastAffectedVersions() bool {
	for _, av := range vi.AffectedVersions {
		if av.LastAffected != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasIntroducedCommits(repo string) bool {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.Introduced != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasFixedCommits(repo string) bool {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.Fixed != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasLastAffectedCommits(repo string) bool {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.LastAffected != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasLimitCommits(repo string) bool {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.Limit != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) FixedCommits(repo string) (FixedCommits []string) {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.Fixed != "" {
			FixedCommits = append(FixedCommits, ac.Fixed)
		}
	}
	return FixedCommits
}

func (vi *VersionInfo) LastAffectedCommits(repo string) (LastAffectedCommits []string) {
	for _, ac := range vi.AffectedCommits {
		if strings.EqualFold(ac.Repo, repo) && ac.LastAffected != "" {
			LastAffectedCommits = append(LastAffectedCommits, ac.Fixed)
		}
	}
	return LastAffectedCommits
}

// Check if the same commit appears in multiple fields of the AffectedCommits array.
// See https://github.com/google/osv.dev/issues/1984 for more context.
func (vi *VersionInfo) Duplicated(candidate AffectedCommit) bool {
	fieldsToCheck := []string{"Introduced", "LastAffected", "Limit", "Fixed"}

	// Get the commit hash to look for.
	v := reflect.ValueOf(&candidate).Elem()

	commit := ""
	for _, field := range fieldsToCheck {
		commit = v.FieldByName(field).String()
		if commit != "" {
			break
		}
	}
	if commit == "" {
		return false
	}

	// Look through what is already present.
	for _, ac := range vi.AffectedCommits {
		v = reflect.ValueOf(&ac).Elem()
		for _, field := range fieldsToCheck {
			existingCommit := v.FieldByName(field).String()
			if existingCommit == commit {
				return true
			}
		}
	}
	return false
}

type CPE struct {
	CPEVersion string
	Part       string
	Vendor     string
	Product    string
	Version    string
	Update     string
	Edition    string
	Language   string
	SWEdition  string
	TargetSW   string
	TargetHW   string
	Other      string
}

var (
	InvalidRepos = []string{
		"https://github.com/ComparedArray/printix-CVE-2022-25089",
		"https://github.com/CVEProject/cvelist",
		"https://github.com/github/cvelist", // Heavily in Advisory URLs, sometimes shows up elsewhere
		"https://github.com/github/securitylab",
		"https://github.com/gitlabhq/gitlabhq", // GitHub mirror, not canonical
		"https://github.com/n0Sleeper/bosscmsVuln",
		"https://github.com/rapid7/metasploit-framework",
		"https://github.com/starnightcyber/miscellaneous",
		"https://gitlab.com/gitlab-org/gitlab-ce",      // redirects to gitlab-foss
		"https://gitlab.com/gitlab-org/gitlab-ee",      // redirects to gitlab
		"https://gitlab.com/gitlab-org/gitlab-foss",    // not the canonical source
		"https://gitlab.com/gitlab-org/omnibus-gitlab", // not the source
	}
	InvalidRepoRegex = `(?i)/(?:(?:CVEs?)|(?:CVE-\d{4}-\d{4,})(?:/?.*)?|bug_report(?:/.*)?|GitHubAssessments/.*)`
)
