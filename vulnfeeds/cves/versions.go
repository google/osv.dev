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
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/sethvargo/go-retry"
	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
)

// References with these tags have been found to contain completely unrelated
// repositories and can be misleading as to the software's true repository,
// Currently not used for this purpose due to undesired false positives
// reducing the number of valid records successfully converted.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these though.
}

// VendorProducts known not to be Open Source software and causing
// cross-contamination of repo derivation between CVEs.
var VendorProductDenyList = []VendorProduct{
	// Causes a chain reaction of incorrect associations from CVE-2022-2068
	// {"netapp", "ontap_select_deploy_administration_utility"},
	// Causes misattribution for Python, e.g. CVE-2022-26488
	// {"netapp", "active_iq_unified_manager"},
	// Causes misattribution for OpenSSH, e.g. CVE-2021-28375
	// {"netapp", "cloud_backup"},
	// Three strikes and the entire netapp vendor is out...
	{"netapp", ""},
	// [CVE-2021-28957]: Incorrectly associates with github.com/lxml/lxml
	{"oracle", "zfs_storage_appliance_kit"},
	{"gradle", "enterprise"}, // The OSS repo gets mis-attributed via CVE-2020-15767
}

type VendorProduct struct {
	Vendor  string
	Product string
}
type VendorProductToRepoMap map[VendorProduct][]string

// Rewrites known GitWeb URLs to their base repository.
func repoGitWeb(parsedURL *url.URL) (string, error) {
	// These repos seem to only be cloneable over git:// not https://
	//
	// The frontend code needs to be taught how to rewrite these back to
	// something clickable for humans in
	// https://github.com/google/osv.dev/blob/master/gcp/website/source_mapper.py
	//
	var gitProtocolHosts = []string{
		"git.code-call-cc.org",
		"git.gnupg.org",
		"git.infradead.org",
	}
	params := strings.FieldsFunc(parsedURL.RawQuery, func(r rune) bool { return r == ';' || r == '&' })
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
	matched, _ := regexp.MatchString(models.InvalidRepoRegex, u)
	if matched {
		return "", fmt.Errorf("%q matched invalid repo regexp", u)
	}

	for _, dr := range models.InvalidRepos {
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
			// Call out to models function for GitWeb URLs
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

		case "git.savannah.gnu.org", "git.savannah.nongnu.org", "git.musl-libc.org":
			repo = strings.Replace(repo, "/cgit", "/git", 1)
		}

		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
			parsedURL.Hostname(), repo), nil
	}

	// Handle a Linux Kernel URL that is already cloneable and doesn't require remapping.
	if parsedURL.Hostname() == "git.kernel.org" && strings.HasPrefix(parsedURL.Path, "/pub/scm/linux/kernel/git/torvalds/linux.git") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Hostname(), "/pub/scm/linux/kernel/git/torvalds/linux.git"), nil
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

	gitSHA1Regex := regexp.MustCompile("^[0-9a-f]{7,40}")

	// "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3"

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		return strings.Split(parsedURL.RawQuery, "=")[1], nil
	}

	// Canonicalized git.kernel.org URLs lose /cgit in the path...
	if parsedURL.Hostname() == "git.kernel.org" &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		return strings.Split(parsedURL.RawQuery, "=")[1], nil
	}

	// GitWeb cgi-bin URLs are structured another way, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070
	if strings.HasPrefix(parsedURL.Path, "/cgi-bin/gitweb.cgi") &&
		strings.Contains(parsedURL.RawQuery, "a=commit") {
		params := strings.FieldsFunc(parsedURL.RawQuery, func(r rune) bool { return r == ';' || r == '&' })
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
	if strings.HasSuffix(directory, "commit/") && gitSHA1Regex.MatchString(possibleCommitHash) {
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
		if strings.HasSuffix(directory, "commits/") && gitSHA1Regex.MatchString(possibleCommitHash) {
			return possibleCommitHash, nil
		}
	}

	// TODO(apollock): add support for resolving a GitHub PR to a commit hash

	// Support for resolving a Github tag to a commit hash
	// example: https://github.com/redis/redis/releases/tag/6.2.17
	if parsedURL.Host == "github.com" {
		possibleCommitHash, err := resolveGitTag(parsedURL, u, gitSHA1Regex)
		if possibleCommitHash != "" && err == nil {
			return possibleCommitHash, nil
		}
	}
	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Commit(): unsupported URL: %s", u)
}

func resolveGitTag(parsedURL *url.URL, u string, gitSHA1Regex *regexp.Regexp) (string, error) {
	directory, tag := path.Split(parsedURL.Path)
	if !strings.HasSuffix(directory, "tag/") {
		return "", errors.New("no tag found")
	}
	tag, err := git.NormalizeVersion(tag)
	if err != nil {
		return "", err
	}

	maybeRepoURL, err := Repo(u)
	if err != nil {
		return "", err
	}

	normalizedTags, err := git.NormalizeRepoTags(maybeRepoURL, nil)
	if err != nil {
		return "", err
	}

	for t, nTag := range normalizedTags {
		if tag == t && gitSHA1Regex.MatchString(nTag.Commit) {
			return nTag.Commit, nil
		}
	}

	return "", errors.New("no tag found")

}

// Detect linkrot and handle link decay in HTTP(S) links via HEAD request with exponential backoff.
func ValidateAndCanonicalizeLink(link string, httpClient *http.Client) (canonicalLink string, err error) {
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
		// default HEAD request in Go does not provide any Accept headers, causing a 406 response.
		req.Header.Set("Accept", "text/html")

		// Send the request
		resp, err := httpClient.Do(req)
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
func ExtractGitCommit(link string, commitType models.CommitType, httpClient *http.Client) (ac models.AffectedCommit, err error) {
	r, err := Repo(link)
	if err != nil {
		return ac, err
	}

	c, err := Commit(link)
	if err != nil {
		return ac, err
	}

	// If URL doesn't validate, treat it as linkrot.
	possiblyDifferentLink, err := ValidateAndCanonicalizeLink(link, httpClient)
	if err != nil {
		return ac, err
	}

	// restart the entire extraction process when the URL changes (i.e. handle a
	// redirect to a completely different host, instead of a redirect within
	// GitHub)
	if possiblyDifferentLink != link {
		return ExtractGitCommit(possiblyDifferentLink, commitType, httpClient)
	}

	ac.SetRepo(r)

	switch commitType {
	case models.Introduced:
		ac.SetIntroduced(c)
	case models.LastAffected:
		ac.SetLastAffected(c)
	case models.Limit:
		ac.SetLimit(c)
	case models.Fixed:
		ac.SetFixed(c)
	}

	return ac, nil
}

func HasVersion(validVersions []string, version string) bool {
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

func ExtractVersionsFromText(validVersions []string, text string) ([]models.AffectedVersion, []string) {
	// Match:
	//  - x.x.x before x.x.x
	//  - x.x.x through x.x.x
	//  - through x.x.x
	//  - before x.x.x
	pattern := regexp.MustCompile(`(?i)([\w.+\-]+)?\s+(through|before)\s+(?:version\s+)?([\w.+\-]+)`)
	matches := pattern.FindAllStringSubmatch(text, -1)
	if matches == nil {
		return nil, []string{"Failed to parse versions from text"}
	}

	var notes []string
	var versions []models.AffectedVersion
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
			notes = append(notes, "Failed to match version range from text")
			continue
		}

		if introduced != "" && !HasVersion(validVersions, introduced) {
			notes = append(notes, fmt.Sprintf("Extracted introduced version %s is not a valid version", introduced))
		}
		if fixed != "" && !HasVersion(validVersions, fixed) {
			notes = append(notes, fmt.Sprintf("Extracted fixed version %s is not a valid version", fixed))
		}
		if lastaffected != "" && !HasVersion(validVersions, lastaffected) {
			notes = append(notes, fmt.Sprintf("Extracted last_affected version %s is not a valid version", lastaffected))
		}
		// Favour fixed over last_affected for schema compliance.
		if fixed != "" && lastaffected != "" {
			lastaffected = ""
		}

		versions = append(versions, models.AffectedVersion{
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

func deduplicateAffectedCommits(commits []models.AffectedCommit) []models.AffectedCommit {
	if len(commits) == 0 {
		return []models.AffectedCommit{}
	}
	slices.SortStableFunc(commits, models.AffectedCommitCompare)
	uniqueCommits := slices.Compact(commits)
	return uniqueCommits
}

func ExtractVersionInfo(cve CVE, validVersions []string, httpClient *http.Client) (v models.VersionInfo, notes []string) {
	for _, reference := range cve.References {
		// (Potentially faulty) Assumption: All viable Git commit reference links are fix commits.
		if commit, err := ExtractGitCommit(reference.Url, models.Fixed, httpClient); err == nil {
			v.AffectedCommits = append(v.AffectedCommits, commit)
		}
	}
	if v.AffectedCommits != nil {
		v.AffectedCommits = deduplicateAffectedCommits(v.AffectedCommits)
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

				if introduced != "" && !HasVersion(validVersions, introduced) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid introduced version", introduced))
				}

				if fixed != "" && !HasVersion(validVersions, fixed) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid fixed version", fixed))
				}

				gotVersions = true
				possibleNewAffectedVersion := models.AffectedVersion{
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
		v.AffectedVersions, extractNotes = ExtractVersionsFromText(validVersions, EnglishDescription(cve.Descriptions))
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
		affectedVersionsWithoutLastAffected := []models.AffectedVersion{}
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
func ParseCPE(formattedString string) (*models.CPE, error) {
	if !strings.HasPrefix(formattedString, "cpe:") {
		return nil, fmt.Errorf("%q does not have expected 'cpe:' prefix", formattedString)
	}

	wfn, err := naming.UnbindFS(formattedString)

	if err != nil {
		return nil, err
	}

	return &models.CPE{
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

func (vp *VendorProduct) UnmarshalText(text []byte) error {
	s := strings.Split(string(text), ":")
	vp.Vendor = s[0]
	vp.Product = s[1]
	return nil
}

func RefAcceptable(ref Reference, tagDenyList []string) bool {
	for _, deniedTag := range tagDenyList {
		if slices.Contains(ref.Tags, deniedTag) {
			return false
		}
	}
	return true
}

// Adds the repo to the cache for the Vendor/Product combination if not already present.
func MaybeUpdateVPRepoCache(cache VendorProductToRepoMap, vp *VendorProduct, repo string) {
	if cache == nil || vp == nil {
		return
	}
	if slices.Contains(cache[*vp], repo) {
		return
	}
	// Avoid poluting the cache with existant-but-useless repos.
	if git.ValidRepoAndHasUsableRefs(repo) {
		cache[*vp] = append(cache[*vp], repo)
	}
}

// Removes the repo from the cache for the Vendor/Product combination if already present.
func MaybeRemoveFromVPRepoCache(cache VendorProductToRepoMap, vp *VendorProduct, repo string) {
	if cache == nil || vp == nil {
		return
	}
	cacheEntry, ok := cache[*vp]
	if !ok {
		return
	}
	if !slices.Contains(cacheEntry, repo) {
		return
	}
	i := slices.Index(cacheEntry, repo)
	if i == -1 {
		return
	}
	// If there is only one entry, delete the entry cache entry.
	if len(cacheEntry) == 1 {
		delete(cache, *vp)
		return
	}
	cacheEntry = slices.Delete(cacheEntry, i, i+1)
	cache[*vp] = cacheEntry
}

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), VersionInfo with AffectedVersions and
// typically no AffectedCommits and attempts to add AffectedCommits (including Fixed commits) where there aren't any.
// Refuses to add the same commit to AffectedCommits more than once.
func GitVersionsToCommits(CVE CVEID, versions models.VersionInfo, repos []string, cache git.RepoTagsCache, Logger utility.LoggerWrapper) (v models.VersionInfo, e error) {
	// versions is a VersionInfo with AffectedVersions and typically no AffectedCommits
	// v is a VersionInfo with AffectedCommits (containing Fixed commits) included
	v = versions
	for _, repo := range repos {
		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			Logger.Warnf("[%s]: Failed to normalize tags for %s: %v", CVE, repo, err)
			continue
		}
		for _, av := range versions.AffectedVersions {
			Logger.Infof("[%s]: Attempting version resolution for %+v using %q", CVE, av, repo)
			introducedEquivalentCommit := ""
			if av.Introduced != "" {
				ac, err := git.VersionToCommit(av.Introduced, repo, models.Introduced, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for introduced version %q from %q: %v", CVE, av.Introduced, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for introduced version %q", CVE, ac, av.Introduced)
					introducedEquivalentCommit = ac.Introduced
				}
			}
			// Only try and convert fixed versions to commits via tags if there aren't any Fixed commits already.
			// ExtractVersionInfo() opportunistically returns
			// AffectedCommits (with Fixed commits) when the CVE has appropriate references, and assuming these references are indeed
			// Fixed commits, they're also assumed to be more precise than what may be derived from tag to commit mapping.
			fixedEquivalentCommit := ""
			if v.HasFixedCommits(repo) && av.Fixed != "" {
				Logger.Infof("[%s]: Using preassumed fixed commits %+v instead of deriving from fixed version %q", CVE, v.FixedCommits(repo), av.Fixed)
			} else if av.Fixed != "" {
				ac, err := git.VersionToCommit(av.Fixed, repo, models.Fixed, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for fixed version %q from %q: %v", CVE, av.Fixed, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for fixed version %q", CVE, ac, av.Fixed)
					fixedEquivalentCommit = ac.Fixed
				}
			}
			// Only try and convert last_affected versions to commits via tags if there aren't any Fixed commits already (to maintain schema compliance).
			// ExtractVersionInfo() opportunistically returns
			// AffectedCommits (with Fixed commits) when the CVE has appropriate references.
			lastAffectedEquivalentCommit := ""
			if !v.HasFixedCommits(repo) && av.LastAffected != "" {
				ac, err := git.VersionToCommit(av.LastAffected, repo, models.LastAffected, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for last_affected version %q from %q: %v", CVE, av.LastAffected, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for last_affected version %q", CVE, ac, av.LastAffected)
					lastAffectedEquivalentCommit = ac.LastAffected
				}
			}
			// Assemble a single AffectedCommit from what was resolved, iff it
			// doesn't result in a half-resolved (false positive-causing)
			// situation with a successfully resolved introduced version and an
			// unsuccessfully resolved fixed or last_affected version.
			ac := models.AffectedCommit{}
			if fixedEquivalentCommit != "" || lastAffectedEquivalentCommit != "" {
				ac.SetRepo(repo)
				if introducedEquivalentCommit != "" {
					ac.SetIntroduced(introducedEquivalentCommit)
				}
				ac.SetFixed(fixedEquivalentCommit)
				ac.SetLastAffected(lastAffectedEquivalentCommit)
			}
			if ac == (models.AffectedCommit{}) {
				// Nothing resolved, move on to the next AffectedVersion
				Logger.Warnf("[%s]: Sufficient resolution not possible for %+v", CVE, av)
				continue
			}
			if ac.InvalidRange() {
				Logger.Warnf("[%s]: Invalid range: %#v", CVE, ac)
				continue
			}
			if v.Duplicated(ac) {
				Logger.Warnf("[%s]: Duplicate: %#v already present in %#v", CVE, ac, v)
				continue
			}
			v.AffectedCommits = append(v.AffectedCommits, ac)
		}
	}
	return v, nil
}

// Examines the CVE references for a CVE and derives repos for it, optionally caching it.
// TODO (jesslowe): refactor with below
func ReposFromReferences(CVE string, cache VendorProductToRepoMap, vp *VendorProduct, refs []Reference, tagDenyList []string, Logger utility.LoggerWrapper) (repos []string) {
	for _, ref := range refs {
		// If any of the denylist tags are in the ref's tag set, it's out of consideration.
		if !RefAcceptable(ref, tagDenyList) {
			// Also remove it if previously added under an acceptable tag.
			MaybeRemoveFromVPRepoCache(cache, vp, ref.Url)
			Logger.Infof("[%s]: disregarding %q for %q due to a denied tag in %q", CVE, ref.Url, vp, ref.Tags)
			continue
		}
		repo, err := Repo(ref.Url)
		if err != nil {
			// Failed to parse as a valid repo.
			continue
		}
		if slices.Contains(repos, repo) {
			continue
		}
		// If the reference is a commit URL, the repo is inherently useful (but only if the repo still ultimately works).
		_, err = Commit(ref.Url)
		// If it's any other repo-shaped URL, it's only useful if it has tags.
		if (err == nil && !git.ValidRepo(repo)) || (err != nil && !git.ValidRepoAndHasUsableRefs(repo)) {
			continue
		}
		repos = append(repos, repo)
		MaybeUpdateVPRepoCache(cache, vp, repo)
	}
	if vp != nil {
		Logger.Infof("[%s]: Derived %q for %q %q using references", CVE, repos, vp.Vendor, vp.Product)
	} else {
		Logger.Infof("[%s]: Derived %q (no CPEs) using references", CVE, repos)
	}

	return repos
}

// Examines the CVE references for a CVE and derives repos for it, optionally caching it.
func ReposFromReferencesCVEList(CVE string, cache VendorProductToRepoMap, vp *VendorProduct, refs []Reference, tagDenyList []string, Logger utility.LoggerWrapper) (repos []string) {
	for _, ref := range refs {
		// If any of the denylist tags are in the ref's tag set, it's out of consideration.
		if !RefAcceptable(ref, tagDenyList) {
			// Also remove it if previously added under an acceptable tag.
			MaybeRemoveFromVPRepoCache(cache, vp, ref.Url)
			Logger.Infof("[%s]: disregarding %q for %q due to a denied tag in %q", CVE, ref.Url, vp, ref.Tags)
			continue
		}
		// if it ends with .md it is likely a researcher repo and _currently_ useless.
		if strings.HasSuffix(ref.Url, ".md") {
			continue
		}
		repo, err := Repo(ref.Url)
		if err != nil {
			// Failed to parse as a valid repo.
			continue
		}
		if slices.Contains(repos, repo) {
			continue
		}
		// If the reference is a commit URL, the repo is inherently useful (but only if the repo still ultimately works).
		_, err = Commit(ref.Url)

		repos = append(repos, repo)
		MaybeUpdateVPRepoCache(cache, vp, repo)
	}
	if vp != nil {
		Logger.Infof("[%s]: Derived %q for %q %q using references", CVE, repos, vp.Vendor, vp.Product)
	} else {
		Logger.Infof("[%s]: Derived %q (no CPEs) using references", CVE, repos)
	}

	return repos
}
