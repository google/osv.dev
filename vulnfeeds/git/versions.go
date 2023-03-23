// Copyright 2023 Google LLC
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

package git

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/google/osv/vulnfeeds/cves"
)

// Take an already normalized version, repo and the pre-normalized mapping of tags to commits and do fuzzy matchingon the version, returning a GitCommit and a bool if successful.
func fuzzyVersionToCommit(normalizedVersion string, repo string, normalizedTags map[string]NormalizedTag) (gc cves.GitCommit, b bool) {
	candidateTags := []string{}
	for _, k := range maps.Keys(normalizedTags) {
		if strings.HasPrefix(k, normalizedVersion) {
			candidateTags = append(candidateTags, k)
		}
	}
	// We may now have one or more tags to further examine for a best choice.
	if len(candidateTags) == 0 {
		return gc, false
	}
	if len(candidateTags) == 1 {
		return cves.GitCommit{
			Repo:   repo,
			Commit: normalizedTags[candidateTags[0]].Commit,
		}, true
	}
	for i, t := range candidateTags {
		// Handle the case where we were given say "12.0", but what we have is "12.0.0"
		if strings.TrimPrefix(t, normalizedVersion) == "-0" {
			return cves.GitCommit{
				Repo:   repo,
				Commit: normalizedTags[candidateTags[i]].Commit,
			}, true
		}
	}
	return gc, false
}

// Take an unnormalized version string, a repo, the pre-normalized mapping of tags to commits and return a GitCommit.
func VersionToCommit(version string, repo string, normalizedTags map[string]NormalizedTag) (gc cves.GitCommit, e error) {
	normalizedVersion, err := cves.NormalizeVersion(version)
	if err != nil {
		return gc, err
	}
	// Try a straight out match first.
	normalizedTag, ok := normalizedTags[normalizedVersion]
	if !ok {
		// Then try to fuzzy-match.
		gc, ok = fuzzyVersionToCommit(normalizedVersion, repo, normalizedTags)
		if !ok {
			return gc, fmt.Errorf("Failed to find a commit for version %q normalized as %q", version, normalizedVersion)
		}
		return gc, nil
	}
	return cves.GitCommit{
		Repo:   repo,
		Commit: normalizedTag.Commit,
	}, nil
}
