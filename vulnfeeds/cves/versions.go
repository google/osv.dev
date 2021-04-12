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
	"net/url"
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

func ExtractVersionInfo(cve CVEItem, validVersions []string) VersionInfo {
	v := VersionInfo{}
	for _, reference := range cve.CVE.References.ReferenceData {
		// TODO(ochang): Support other common commit URLs.
		if commit := extractGitHubCommit(reference.URL); commit != nil {
			v.FixCommits = append(v.FixCommits, *commit)
		}
	}

	for _, node := range cve.Configurations.Nodes {
		if node.Operator != "OR" {
			continue
		}

		// TODO: Also try to parse description as these are not always reliably set.
		for _, match := range node.CPEMatch {
			if !match.Vulnerable {
				continue
			}

			if match.VersionStartIncluding != "" || match.VersionEndExcluding != "" {
				if match.VersionStartExcluding != "" || match.VersionEndIncluding != "" {
					// TODO: handle these by using validVersions.
					continue
				}

				v.AffectedVersions = append(v.AffectedVersions, AffectedVersion{
					// TODO: make sure these match validVersions.
					Introduced: match.VersionStartIncluding,
					Fixed:      match.VersionEndExcluding,
				})
			}
		}
	}
	return v
}
