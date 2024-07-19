// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cves

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/sethvargo/go-retry"
	"golang.org/x/exp/slices"
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

// Synthetic enum of supported commit types.
type CommitType int

const (
	Introduced CommitType = iota
	Fixed
	Limit
	LastAffected
)

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

// Rewrites known GitWeb URLs to their base repository.
func repoGitWeb(parsedURL *url.URL) (string, error) {
	// These repos seem to only be cloneable over git:// not https://
	//
	// The frontend code needs to be taught how to rewrite these back to
	// something clickable for humans in
	// https://github.com/google/osv.dev/blob/master/gcp/appengine/source_mapper.py
	//
	var gitProtocolHosts = []string{
		"git.code-call-cc.org",
		"git.gnupg.org",
		"git.infradead.org",
	}
	params := strings.Split(parsedURL.RawQuery, ";")
	for _, param := range params {
		if !strings.HasPrefix(param, "p=") {
			continue
		}
		repo, err := url.JoinPath(strings.TrimSuffix(strings.TrimSuffix(parsedURL.Path, "/gitweb.cgi"), "cgi-bin"), strings.Split(param, "=")[1])
		if err != nil {
			return "", err
		}
		if slices.Contains(gitProtocolHosts, parsedURL.Hostname()) {
			return fmt.Sprintf("git://%s%s", parsedURL.Hostname(), repo), nil
		}
		return fmt.Sprintf("https://%s%s", parsedURL.Hostname(), repo), nil
	}
	return "", fmt.Errorf("unsupported GitWeb URL: %s", parsedURL.String())
}

// Returns the base repository URL for supported repository hosts.
func Repo(u string) (string, error) {
	var supportedHosts = []string{
		"bitbucket.org",
		"github.com",
		"gitlab.com",
		"gitlab.org",
		"opendev.org",
		"pagure.io",
		"sourceware.org",
		"xenbits.xen.org",
	}
	var supportedHostPrefixes = []string{
		"git",
		"gitlab",
	}
	parsedURL, err := url.Parse(strings.TrimSuffix(u, "/"))
	if err != nil {
		return "", err
	}

	// Disregard the repos we know we don't like (by regex).
	matched, _ := regexp.MatchString(InvalidRepoRegex, u)
	if matched {
		return "", fmt.Errorf("%q matched invalid repo regexp", u)
	}

	for _, dr := range InvalidRepos {
		if strings.HasPrefix(u, dr) {
			return "", fmt.Errorf("%q found in denylist", u)
		}
	}

	// Were we handed a base repository URL from the get go?
	if slices.Contains(supportedHosts, parsedURL.Hostname()) || slices.Contains(supportedHostPrefixes, strings.Split(parsedURL.Hostname(), ".")[0]) {
		pathParts := strings.Split(parsedURL.Path, "/")
		if len(pathParts) == 3 && !strings.Contains(parsedURL.Path, "gitweb") && parsedURL.Hostname() != "sourceware.org" {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(), parsedURL.Path),
				nil
		}
		// GitLab can have a deeper structure to a repo (projects can be within nested groups)
		if len(pathParts) >= 3 && strings.HasPrefix(parsedURL.Hostname(), "gitlab.") &&
			!(strings.Contains(parsedURL.Path, "commit") ||
				strings.Contains(parsedURL.Path, "compare") ||
				strings.Contains(parsedURL.Path, "blob") ||
				strings.Contains(parsedURL.Path, "releases/tag") ||
				strings.Contains(parsedURL.Path, "releases") ||
				strings.Contains(parsedURL.Path, "tags") ||
				strings.Contains(parsedURL.Path, "security/advisories") ||
				strings.Contains(parsedURL.Path, "issues")) {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(), parsedURL.Path),
				nil
		}
		if len(pathParts) == 2 && parsedURL.Hostname() == "git.netfilter.org" {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(), parsedURL.Path),
				nil
		}
		if len(pathParts) >= 2 && parsedURL.Hostname() == "git.ffmpeg.org" {
			return fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Hostname(), pathParts[2]), nil
		}
		if parsedURL.Hostname() == "sourceware.org" {
			// Call out to common function for GitWeb URLs
			return repoGitWeb(parsedURL)
		}
		if parsedURL.Hostname() == "git.postgresql.org" {
			// PostgreSQL's GitWeb is at a different path to its Git repo.
			parsedURL.Path = strings.Replace(parsedURL.Path, "gitweb", "git", 1)
			return repoGitWeb(parsedURL)
		}
		if strings.HasSuffix(parsedURL.Path, ".git") {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					parsedURL.Path),
				nil
		}
	}

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	//
	// They also sometimes have characteristics to map from a web-friendly URL to a clone-friendly repo, on a host-by-host basis.
	//
	//	https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git [web browseable]
	//	https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git [cloneable]
	//
	//	https://git.savannah.gnu.org/cgit/emacs.git [web browseable]
	//	https://git.savannah.gnu.org/git/emacs.git [cloneable]
	//
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		repo := strings.TrimSuffix(parsedURL.Path, "/commit/")

		switch parsedURL.Hostname() {
		case "git.kernel.org":
			repo = strings.Replace(repo, "/cgit", "/pub/scm", 1)

		case "git.savannah.gnu.org":
		case "git.savannah.nongnu.org":
			repo = strings.Replace(repo, "/cgit", "/git", 1)
		}

		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
			parsedURL.Hostname(), repo), nil
	}

	// GitWeb CGI URLs are structured very differently, and require significant translation to get a cloneable URL, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070 -> git://git.gnupg.org/libksba.git
	// https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=11d171f1910b508a81d21faa087ad1af573407d8 -> git://sourceware.org/git/binutils-gdb.git
	if strings.HasSuffix(parsedURL.Path, "/gitweb.cgi") &&
		strings.HasPrefix(parsedURL.RawQuery, "p=") {
		return repoGitWeb(parsedURL)
	}

	// Variations of Git Web URLs, e.g.
	// https://git.tukaani.org/?p=xz.git;a=tags

	// starts with a supported host and querystring contains p=\*.git
	if (slices.Contains(supportedHosts, parsedURL.Hostname()) || slices.Contains(supportedHostPrefixes, strings.Split(parsedURL.Hostname(), ".")[0])) &&
		(strings.HasPrefix(parsedURL.RawQuery, "p=") && strings.Contains(parsedURL.RawQuery, ".git")) {
		return repoGitWeb(parsedURL)
	}

	// cgit.freedesktop.org is a special snowflake with enough repos to warrant special handling
	// it is a mirror of gitlab.freedesktop.org
	// https://cgit.freedesktop.org/xorg/lib/libXRes/commit/?id=c05c6d918b0e2011d4bfa370c321482e34630b17
	// https://cgit.freedesktop.org/xorg/lib/libXRes
	// http://cgit.freedesktop.org/spice/spice/refs/tags
	if parsedURL.Hostname() == "cgit.freedesktop.org" {
		if strings.HasSuffix(parsedURL.Path, "commit/") &&
			strings.HasPrefix(parsedURL.RawQuery, "id=") {
			repo := strings.TrimSuffix(parsedURL.Path, "/commit/")
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				repo), nil
		}
		if strings.HasSuffix(parsedURL.Path, "refs/tags") {
			repo := strings.TrimSuffix(parsedURL.Path, "/refs/tags")
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				repo), nil
		}
		if len(strings.Split(parsedURL.Path, "/")) == 4 {
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				parsedURL.Path), nil
		}
	}

	// GitLab URLs with hyphens in them may have an arbitrary path to the final repo, e.g.
	// https://gitlab.com/mayan-edms/mayan-edms/-/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e
	// https://gitlab.freedesktop.org/xorg/lib/libxpm/-/commit/a3a7c6dcc3b629d7650148
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4
	// https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2501.json
	if strings.HasPrefix(parsedURL.Hostname(), "gitlab.") && strings.Contains(parsedURL.Path, "/-/") &&
		(strings.Contains(parsedURL.Path, "commit") ||
			strings.Contains(parsedURL.Path, "blob") ||
			strings.Contains(parsedURL.Path, "releases/tag") ||
			strings.Contains(parsedURL.Path, "releases") ||
			strings.Contains(parsedURL.Path, "tags") ||
			strings.Contains(parsedURL.Path, "security/advisories") ||
			strings.Contains(parsedURL.Path, "issues")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Split(parsedURL.Path, "/-/")[0]),
			nil
	}

	// GitHub and GitLab URLs not matching the previous e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://github.com/tensorflow/tensorflow/blob/master/tensorflow/core/ops/math_ops.cc
	// https://gitlab.com/mayan-edms/mayan-edms/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e (this assumes "two-directory" deep repos)
	//
	// This also supports GitHub tag URLs, e.g.
	// https://github.com/JonMagon/KDiskMark/releases/tag/3.1.0
	//
	// This also supports GitHub and Gitlab issue URLs, e.g.:
	// https://github.com/axiomatic-systems/Bento4/issues/755
	// https://gitlab.com/wireshark/wireshark/-/issues/18307
	//
	// This also supports GitHub Security Advisory URLs, e.g.
	// https://github.com/ballcat-projects/ballcat-codegen/security/advisories/GHSA-fv3m-xhqw-9m79

	if (parsedURL.Hostname() == "github.com" || strings.HasPrefix(parsedURL.Hostname(), "gitlab.")) &&
		(strings.Contains(parsedURL.Path, "commit") ||
			strings.Contains(parsedURL.Path, "blob") ||
			strings.Contains(parsedURL.Path, "releases/tag") ||
			strings.Contains(parsedURL.Path, "releases") ||
			strings.Contains(parsedURL.Path, "tags") ||
			strings.Contains(parsedURL.Path, "security/advisories") ||
			strings.Contains(parsedURL.Path, "issues")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// GitHub pull request and comparison URLs are structured differently, e.g.
	// https://github.com/kovidgoyal/kitty/compare/v0.26.1...v0.26.2
	// https://gitlab.com/mayan-edms/mayan-edms/-/compare/development...master
	// https://git.drupalcode.org/project/views/-/compare/7.x-3.21...7.x-3.x
	if strings.Contains(parsedURL.Path, "compare") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// GitHub pull request URLs are structured differently, e.g.
	// https://github.com/google/osv.dev/pull/738
	if parsedURL.Hostname() == "github.com" &&
		strings.Contains(parsedURL.Path, "pull") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// Gitlab merge request URLs are structured differently, e.g.
	// https://gitlab.com/libtiff/libtiff/-/merge_requests/378
	if strings.HasPrefix(parsedURL.Hostname(), "gitlab.") &&
		strings.Contains(parsedURL.Path, "merge_requests") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// Bitbucket.org URLs are another snowflake, e.g.
	// https://bitbucket.org/ianb/pastescript/changeset/a19e462769b4
	// https://bitbucket.org/jespern/django-piston/commits/91bdaec89543/
	// https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1
	// https://bitbucket.org/snakeyaml/snakeyaml/pull-requests/35
	// https://bitbucket.org/snakeyaml/snakeyaml/issues/566
	// https://bitbucket.org/snakeyaml/snakeyaml/downloads/?tab=tags
	if parsedURL.Hostname() == "bitbucket.org" &&
		(strings.Contains(parsedURL.Path, "changeset") ||
			strings.Contains(parsedURL.Path, "downloads") ||
			strings.Contains(parsedURL.Path, "wiki") ||
			strings.Contains(parsedURL.Path, "issues") ||
			strings.Contains(parsedURL.Path, "security") ||
			strings.Contains(parsedURL.Path, "pull-requests") ||
			strings.Contains(parsedURL.Path, "commits")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Repo(): unsupported URL: %s", u)
}

// Returns the commit ID from supported links.
func Commit(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		return strings.Split(parsedURL.RawQuery, "=")[1], nil
	}

	// GitWeb cgi-bin URLs are structured another way, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070
	if strings.HasPrefix(parsedURL.Path, "/cgi-bin/gitweb.cgi") &&
		strings.Contains(parsedURL.RawQuery, "a=commit") {
		params := strings.Split(parsedURL.RawQuery, ";")
		for _, param := range params {
			if !strings.HasPrefix(param, "h=") {
				continue
			}
			return strings.Split(param, "=")[1], nil
		}
	}

	// FFMpeg's GitWeb seems to be it's own unique snowflake, e.g.
	// https://git.ffmpeg.org/gitweb/ffmpeg.git/commit/c94875471e3ba3dc396c6919ff3ec9b14539cd71
	if strings.HasPrefix(parsedURL.Path, "/gitweb/") && len(strings.Split(parsedURL.Path, "/")) == 5 {
		return strings.Split(parsedURL.Path, "/")[4], nil
	}

	// GitHub and GitLab commit URLs are structured one way, e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4

	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	directory, possibleCommitHash := path.Split(parsedURL.Path)
	if strings.HasSuffix(directory, "commit/") {
		return strings.TrimSuffix(possibleCommitHash, ".patch"), nil
	}

	// and Bitbucket.org commit URLs are similiar yet slightly different:
	// https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1
	//
	// Some bitbucket.org commit URLs have been observed in the wild with a trailing /, which will
	// change the behaviour of path.Split(), so normalize the path to be tolerant of this.
	if parsedURL.Host == "bitbucket.org" {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
		directory, possibleCommitHash := path.Split(parsedURL.Path)
		if strings.HasSuffix(directory, "commits/") {
			return possibleCommitHash, nil
		}
	}

	// TODO(apollock): add support for resolving a GitHub PR to a commit hash

	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Commit(): unsupported URL: %s", u)
}

// Detect linkrot and handle link decay in HTTP(S) links via HEAD request with exponential backoff.
func ValidateAndCanonicalizeLink(link string) (canonicalLink string, err error) {
	u, err := url.Parse(link)
	if !slices.Contains([]string{"http", "https"}, u.Scheme) {
		// Handle what's presumably a git:// URL.
		return link, err
	}
	backoff := retry.NewExponential(1 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		req, err := http.NewRequest("HEAD", link, nil)
		if err != nil {
			return err
		}

		// security.alpinelinux.org responds with text/html content.
		req.Header.Set("Accept", "text/html")

		// Send the request
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		switch resp.StatusCode / 100 {
		// 4xx response codes are an instant fail.
		case 4:
			return fmt.Errorf("bad response: %v", resp.StatusCode)
		// 5xx response codes are retriable.
		case 5:
			return retry.RetryableError(fmt.Errorf("bad response: %v", resp.StatusCode))
		// Anything else is acceptable.
		default:
			canonicalLink = resp.Request.URL.String()
			return nil
		}
	}); err != nil {
		return link, fmt.Errorf("unable to determine validity of %q: %v", link, err)
	}
	return canonicalLink, nil
}

// For URLs referencing commits in supported Git repository hosts, return a cloneable AffectedCommit.
func extractGitCommit(link string, commitType CommitType) (ac AffectedCommit, err error) {
	r, err := Repo(link)
	if err != nil {
		return ac, err
	}

	c, err := Commit(link)
	if err != nil {
		return ac, err
	}

	// If URL doesn't validate, treat it as linkrot.
	// Possible TODO(apollock): restart the entire extraction process when the
	// repo changes (i.e. handle a redirect to a completely different host,
	// instead of a redirect within GitHub)
	r, err = ValidateAndCanonicalizeLink(r)
	if err != nil {
		return ac, err
	}

	ac.SetRepo(r)

	switch commitType {
	case Introduced:
		ac.SetIntroduced(c)
	case LastAffected:
		ac.SetLastAffected(c)
	case Limit:
		ac.SetLimit(c)
	case Fixed:
		ac.SetFixed(c)
	}

	return ac, nil
}

func hasVersion(validVersions []string, version string) bool {
	if len(validVersions) == 0 {
		return true
	}
	return versionIndex(validVersions, version) != -1
}

func versionIndex(validVersions []string, version string) int {
	for i, cur := range validVersions {
		if cur == version {
			return i
		}
	}
	return -1
}

func nextVersion(validVersions []string, version string) (string, error) {
	idx := versionIndex(validVersions, version)
	if idx == -1 {
		return "", fmt.Errorf("warning: %s is not a valid version", version)
	}

	idx += 1
	if idx >= len(validVersions) {
		return "", fmt.Errorf("warning: %s does not have a version that comes after", version)
	}

	return validVersions[idx], nil
}

func processExtractedVersion(version string) string {
	version = strings.Trim(version, ".")
	// Version should contain at least a "." or a number.
	if !strings.ContainsAny(version, ".") && !strings.ContainsAny(version, "0123456789") {
		return ""
	}

	return version
}

func extractVersionsFromDescription(validVersions []string, description string) ([]AffectedVersion, []string) {
	// Match:
	//  - x.x.x before x.x.x
	//  - x.x.x through x.x.x
	//  - through x.x.x
	//  - before x.x.x
	pattern := regexp.MustCompile(`(?i)([\w.+\-]+)?\s+(through|before)\s+(?:version\s+)?([\w.+\-]+)`)
	matches := pattern.FindAllStringSubmatch(description, -1)
	if matches == nil {
		return nil, []string{"Failed to parse versions from description"}
	}

	var notes []string
	var versions []AffectedVersion
	for _, match := range matches {
		// Trim periods that are part of sentences.
		introduced := processExtractedVersion(match[1])
		fixed := processExtractedVersion(match[3])
		lastaffected := ""
		if match[2] == "through" {
			// "Through" implies inclusive range, so the fixed version is the one that comes after.
			var err error
			fixed, err = nextVersion(validVersions, fixed)
			if err != nil {
				notes = append(notes, err.Error())
				// if that inference failed, we know this version was definitely still vulnerable.
				lastaffected = cleanVersion(match[3])
				notes = append(notes, fmt.Sprintf("Using %s as last_affected version instead", cleanVersion(match[3])))
			}
		}

		if introduced == "" && fixed == "" && lastaffected == "" {
			notes = append(notes, "Failed to match version range from description")
			continue
		}

		if introduced != "" && !hasVersion(validVersions, introduced) {
			notes = append(notes, fmt.Sprintf("Extracted introduced version %s is not a valid version", introduced))
		}
		if fixed != "" && !hasVersion(validVersions, fixed) {
			notes = append(notes, fmt.Sprintf("Extracted fixed version %s is not a valid version", fixed))
		}
		if lastaffected != "" && !hasVersion(validVersions, lastaffected) {
			notes = append(notes, fmt.Sprintf("Extracted last_affected version %s is not a valid version", lastaffected))
		}
		// Favour fixed over last_affected for schema compliance.
		if fixed != "" && lastaffected != "" {
			lastaffected = ""
		}

		versions = append(versions, AffectedVersion{
			Introduced:   introduced,
			Fixed:        fixed,
			LastAffected: lastaffected,
		})
	}

	return versions, notes
}

func cleanVersion(version string) string {
	// Versions can end in ":" for some reason.
	return strings.TrimRight(version, ":")
}

func ExtractVersionInfo(cve CVE, validVersions []string) (v VersionInfo, notes []string) {
	for _, reference := range cve.References {
		// (Potentially faulty) Assumption: All viable Git commit reference links are fix commits.
		if commit, err := extractGitCommit(reference.Url, Fixed); err == nil {
			v.AffectedCommits = append(v.AffectedCommits, commit)
		}
	}

	gotVersions := false
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			if node.Operator != "OR" {
				continue
			}

			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}

				introduced := ""
				fixed := ""
				lastaffected := ""
				if match.VersionStartIncluding != nil {
					introduced = cleanVersion(*match.VersionStartIncluding)
				} else if match.VersionStartExcluding != nil {
					var err error
					introduced, err = nextVersion(validVersions, cleanVersion(*match.VersionStartExcluding))
					if err != nil {
						notes = append(notes, err.Error())
					}
				}

				if match.VersionEndExcluding != nil {
					fixed = cleanVersion(*match.VersionEndExcluding)
				} else if match.VersionEndIncluding != nil {
					var err error
					// Infer the fixed version from the next version after.
					fixed, err = nextVersion(validVersions, cleanVersion(*match.VersionEndIncluding))
					if err != nil {
						notes = append(notes, err.Error())
						// if that inference failed, we know this version was definitely still vulnerable.
						lastaffected = cleanVersion(*match.VersionEndIncluding)
						notes = append(notes, fmt.Sprintf("Using %s as last_affected version instead", cleanVersion(*match.VersionEndIncluding)))
					}
				}

				if introduced == "" && fixed == "" && lastaffected == "" {
					// See if a last affected version is inferable from the CPE string.
					// In this situation there is no known introduced version.
					CPE, err := ParseCPE(match.Criteria)
					if err != nil {
						continue
					}
					if CPE.Part != "a" {
						// Skip operating system CPEs.
						continue
					}
					if slices.Contains([]string{"NA", "ANY"}, CPE.Version) {
						// These are meaningless converting to commits.
						continue
					}
					lastaffected = CPE.Version
					if CPE.Update != "ANY" {
						lastaffected += "-" + CPE.Update
					}
				}

				if introduced == "" && fixed == "" && lastaffected == "" {
					continue
				}

				if introduced != "" && !hasVersion(validVersions, introduced) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid introduced version", introduced))
				}

				if fixed != "" && !hasVersion(validVersions, fixed) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid fixed version", fixed))
				}

				gotVersions = true
				possibleNewAffectedVersion := AffectedVersion{
					Introduced:   introduced,
					Fixed:        fixed,
					LastAffected: lastaffected,
				}
				if slices.Contains(v.AffectedVersions, possibleNewAffectedVersion) {
					// Avoid appending duplicates
					continue
				}
				v.AffectedVersions = append(v.AffectedVersions, possibleNewAffectedVersion)
			}
		}
	}
	if !gotVersions {
		var extractNotes []string
		v.AffectedVersions, extractNotes = extractVersionsFromDescription(validVersions, EnglishDescription(cve))
		notes = append(notes, extractNotes...)
		if len(v.AffectedVersions) > 0 {
			log.Printf("[%s] Extracted versions from description = %+v", cve.ID, v.AffectedVersions)
		}
	}

	if len(v.AffectedVersions) == 0 {
		notes = append(notes, "No versions detected.")
	}

	if len(notes) != 0 && len(validVersions) > 0 {
		notes = append(notes, "Valid versions:")
		for _, version := range validVersions {
			notes = append(notes, "  - "+version)
		}
	}

	// Remove any lastaffected versions in favour of fixed versions.
	if v.HasFixedVersions() {
		affectedVersionsWithoutLastAffected := []AffectedVersion{}
		for _, av := range v.AffectedVersions {
			if av.LastAffected != "" {
				continue
			}
			affectedVersionsWithoutLastAffected = append(affectedVersionsWithoutLastAffected, av)
		}
		v.AffectedVersions = affectedVersionsWithoutLastAffected
	}
	return v, notes
}

func CPEs(cve CVE) []string {
	var cpes []string
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				cpes = append(cpes, match.Criteria)
			}
		}
	}

	return cpes
}

// There are some weird and wonderful rules about quoting with strings in CPEs
// See 5.3.2 of NISTIR 7695 for more details
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
func RemoveQuoting(s string) (result string) {
	return strings.Replace(s, "\\", "", -1)
}

// Parse a well-formed CPE string into a struct.
func ParseCPE(formattedString string) (*CPE, error) {
	if !strings.HasPrefix(formattedString, "cpe:") {
		return nil, fmt.Errorf("%q does not have expected 'cpe:' prefix", formattedString)
	}

	wfn, err := naming.UnbindFS(formattedString)

	if err != nil {
		return nil, err
	}

	return &CPE{
		CPEVersion: strings.Split(formattedString, ":")[1],
		Part:       wfn.GetString("part"),
		Vendor:     RemoveQuoting(wfn.GetString("vendor")),
		Product:    RemoveQuoting(wfn.GetString("product")),
		Version:    RemoveQuoting(wfn.GetString("version")),
		Update:     wfn.GetString("update"),
		Edition:    wfn.GetString("edition"),
		Language:   wfn.GetString("language"),
		SWEdition:  wfn.GetString("sw_edition"),
		TargetSW:   wfn.GetString("target_sw"),
		TargetHW:   wfn.GetString("target_hw"),
		Other:      wfn.GetString("other")}, nil
}

// Normalize version strings found in CVE CPE Match data or Git tags.
// Use the same logic and behaviour as normalize_tag() osv/bug.py for consistency.
func NormalizeVersion(version string) (normalizedVersion string, e error) {
	// Keep in sync with the intent of https://github.com/google/osv.dev/blob/26050deb42785bc5a4dc7d802eac8e7f95135509/osv/bug.py#L31
	var validVersion = regexp.MustCompile(`(?i)(\d+|(?:rc|alpha|beta|preview)\d*)`)
	var validVersionText = regexp.MustCompile(`(?i)(?:rc|alpha|beta|preview)\d*`)
	components := validVersion.FindAllString(version, -1)
	if components == nil {
		return "", fmt.Errorf("%q is not a supported version", version)
	}
	// If the very first component happens to accidentally match the strings we support, remove it.
	// This is necessary because of the lack of negative lookbehind assertion support in RE2.
	if validVersionText.MatchString(components[0]) {
		components = slices.Delete(components, 0, 1)
	}
	normalizedVersion = strings.Join(components, "-")
	return normalizedVersion, e
}
