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
	"fmt"
	"log"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	"golang.org/x/exp/slices"
)

type FixCommit struct {
	Repo   string
	Commit string
}

type AffectedVersion struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

type VersionInfo struct {
	FixCommits       []FixCommit
	AffectedVersions []AffectedVersion
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

// Returns the base repository URL for supported repository hosts.
func Repo(u string) (string, error) {
	var supportedHosts = []string{
		"github.com",
		"gitlab.org",
		"bitbucket.org",
	}
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	// Were we handed a base repository URL from the get go?
	if slices.Contains(supportedHosts, parsedURL.Hostname()) {
		if len(strings.Split(strings.TrimSuffix(parsedURL.Path, "/"), "/")) == 3 {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					strings.TrimSuffix(parsedURL.Path, "/")),
				nil
		}
	}

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		repo := strings.TrimSuffix(parsedURL.Path, "/commit/")
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
			parsedURL.Hostname(), repo), nil
	}

	// GitWeb CGI URLs are structured very differently, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070 is another variation seen in the wild
	if strings.HasPrefix(parsedURL.Path, "/cgi-bin/gitweb.cgi") &&
		strings.HasPrefix(parsedURL.RawQuery, "p=") {
		params := strings.Split(parsedURL.RawQuery, ";")
		for _, param := range params {
			if !strings.HasPrefix(param, "p=") {
				continue
			}
			repo := strings.Split(param, "=")[1]
			return fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Hostname(), repo), nil
		}
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

	// GitHub and GitLab commit and blob URLs are structured one way, e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://github.com/tensorflow/tensorflow/blob/master/tensorflow/core/ops/math_ops.cc
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4
	// https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2501.json
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

	// GitHub and GitLab commit URLs are structured one way, e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4
	// and Bitbucket.org commit URLs are similiar yet slightly different:
	// https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1
	//
	// Some bitbucket.org commit URLs have been observed in the wild with a trailing /, which will
	// change the behaviour of path.Split(), so normalize the path to be tolerant of this.
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	directory, possibleCommitHash := path.Split(parsedURL.Path)
	if strings.HasSuffix(directory, "commit/") || strings.HasSuffix(directory, "commits/") {
		return possibleCommitHash, nil
	}

	// TODO(apollock): add support for resolving a GitHub PR to a commit hash

	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Commit(): unsupported URL: %s", u)
}

// For URLs referencing commits in supported Git repository hosts, return a FixCommit.
func extractGitCommit(link string) *FixCommit {
	r, err := Repo(link)
	if err != nil {
		return nil
	}

	c, err := Commit(link)
	if err != nil {
		return nil
	}

	return &FixCommit{
		Repo:   r,
		Commit: c,
	}
}

func hasVersion(validVersions []string, version string) bool {
	if validVersions == nil || len(validVersions) == 0 {
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
		return "", fmt.Errorf("Warning: %s is not a valid version", version)
	}

	idx += 1
	if idx >= len(validVersions) {
		return "", fmt.Errorf("Warning: %s does not have a version that comes after.", version)
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
		if match[2] == "through" {
			// "Through" implies inclusive range, so the fixed version is the one that comes after.
			var err error
			fixed, err = nextVersion(validVersions, fixed)
			if err != nil {
				notes = append(notes, err.Error())
			}
		}

		if introduced == "" && fixed == "" {
			notes = append(notes, "Failed to match version range from description")
			continue
		}

		if introduced != "" && !hasVersion(validVersions, introduced) {
			notes = append(notes, fmt.Sprintf("Extracted version %s is not a valid version", introduced))
		}
		if fixed != "" && !hasVersion(validVersions, fixed) {
			notes = append(notes, fmt.Sprintf("Extracted version %s is not a valid version", fixed))
		}

		versions = append(versions, AffectedVersion{
			Introduced: introduced,
			Fixed:      fixed,
		})
	}

	return versions, notes
}

func cleanVersion(version string) string {
	// Versions can end in ":" for some reason.
	return strings.TrimRight(version, ":")
}

func ExtractVersionInfo(cve CVEItem, validVersions []string) (v VersionInfo, notes []string) {
	for _, reference := range cve.CVE.References.ReferenceData {
		if commit := extractGitCommit(reference.URL); commit != nil {
			v.FixCommits = append(v.FixCommits, *commit)
		}
	}

	gotVersions := false
	for _, node := range cve.Configurations.Nodes {
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
			if match.VersionStartIncluding != "" {
				introduced = cleanVersion(match.VersionStartIncluding)
			} else if match.VersionStartExcluding != "" {
				var err error
				introduced, err = nextVersion(validVersions, cleanVersion(match.VersionStartExcluding))
				if err != nil {
					notes = append(notes, err.Error())
				}
			}

			if match.VersionEndExcluding != "" {
				fixed = cleanVersion(match.VersionEndExcluding)
			} else if match.VersionEndIncluding != "" {
				var err error
				// Infer the fixed version from the next version after.
				fixed, err = nextVersion(validVersions, cleanVersion(match.VersionEndIncluding))
				if err != nil {
					notes = append(notes, err.Error())
					// if that inference failed, we know this version was definitely still vulnerable.
					lastaffected = cleanVersion(match.VersionEndIncluding)
					notes = append(notes, fmt.Sprintf("Using %s as last_affected version instead", cleanVersion(match.VersionEndIncluding)))
				}
			}

			if introduced == "" && fixed == "" {
				continue
			}

			if introduced != "" && !hasVersion(validVersions, introduced) {
				notes = append(notes, fmt.Sprintf("Warning: %s is not a valid introduced version", introduced))
			}

			if fixed != "" && !hasVersion(validVersions, fixed) {
				notes = append(notes, fmt.Sprintf("Warning: %s is not a valid fixed version", fixed))
			}

			gotVersions = true
			v.AffectedVersions = append(v.AffectedVersions, AffectedVersion{
				Introduced:   introduced,
				Fixed:        fixed,
				LastAffected: lastaffected,
			})
		}
	}
	if !gotVersions {
		var extractNotes []string
		v.AffectedVersions, extractNotes = extractVersionsFromDescription(validVersions, EnglishDescription(cve.CVE))
		notes = append(notes, extractNotes...)
		if len(v.AffectedVersions) > 0 {
			log.Printf("[%s] Extracted versions from description = %+v", cve.CVE.CVEDataMeta.ID, v.AffectedVersions)
		}
	}

	if len(v.AffectedVersions) == 0 {
		notes = append(notes, "No versions detected.")
	}

	if len(notes) != 0 {
		notes = append(notes, "Valid versions:")
		for _, version := range validVersions {
			notes = append(notes, "  - "+version)
		}
	}
	return v, notes
}

func CPEs(cve CVEItem) []string {
	var cpes []string
	for _, node := range cve.Configurations.Nodes {
		for _, match := range node.CPEMatch {
			cpes = append(cpes, match.CPE23URI)
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
func Normalize(version string) (normalizedVersion string, e error) {
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
