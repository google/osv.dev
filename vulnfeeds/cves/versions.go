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
	"regexp"
	"strings"
)

type FixCommit struct {
	Repo   string
	Commit string
}

type AffectedVersion struct {
	Introduced string
	Fixed      string
}

type VersionInfo struct {
	FixCommits       []FixCommit
	AffectedVersions []AffectedVersion
}

func extractGitHubCommit(link string) *FixCommit {
	// Example: https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	if u.Host != "github.com" {
		return nil
	}

	pathParts := strings.Split(u.Path, "/")
	if pathParts[len(pathParts)-2] != "commit" {
		return nil
	}

	// Commit is the last component.
	commit := pathParts[len(pathParts)-1]
	// Stript the /commit/... to get the repo URL.
	u.Path = strings.Join(pathParts[0:len(pathParts)-2], "/")
	repo := u.String()

	return &FixCommit{
		Repo:   repo,
		Commit: commit,
	}
}

func hasVersion(validVersions []string, version string) bool {
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

		versions = append(versions, AffectedVersion{
			Introduced: introduced,
			Fixed:      fixed,
		})
	}

	return versions, notes
}

func ExtractVersionInfo(cve CVEItem, validVersions []string) (VersionInfo, []string) {
	var notes []string
	v := VersionInfo{}
	for _, reference := range cve.CVE.References.ReferenceData {
		// TODO(ochang): Support other common commit URLs.
		if commit := extractGitHubCommit(reference.URL); commit != nil {
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
			if match.VersionStartIncluding != "" {
				introduced = match.VersionStartIncluding
			} else if match.VersionStartExcluding != "" {
				var err error
				introduced, err = nextVersion(validVersions, match.VersionStartExcluding)
				if err != nil {
					notes = append(notes, err.Error())
				}
			}

			if match.VersionEndExcluding != "" {
				fixed = match.VersionEndExcluding
			} else if match.VersionEndIncluding != "" {
				var err error
				fixed, err = nextVersion(validVersions, match.VersionEndIncluding)
				if err != nil {
					notes = append(notes, err.Error())
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
				Introduced: introduced,
				Fixed:      fixed,
			})
		}
	}

	if !gotVersions {
		var extractNotes []string
		v.AffectedVersions, extractNotes = extractVersionsFromDescription(validVersions, EnglishDescription(cve.CVE))
		notes = append(notes, extractNotes...)
		log.Printf("Extracted versions from description = %+v", v.AffectedVersions)
	}

	if len(v.AffectedVersions) == 0 {
		notes = append(notes, "No versions detected.")
	}
	return v, notes
}
