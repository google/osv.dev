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
	"regexp"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/google/osv/vulnfeeds/cves"
)

// Take an already normalized version, repo and the mapping of repo tags
// normalized tags and commits and do fuzzy matching version, returning a
// GitCommit and a bool if successful.
func fuzzyVersionToCommit(normalizedVersion string, repo string, commitType cves.CommitType, normalizedTags map[string]NormalizedTag) (ac cves.AffectedCommit, b bool) {
	candidateTags := []string{} // the subset of normalizedTags tags that might be appropriate to use as a fuzzy match for normalizedVersion.
	// Keep in sync with the regex in cves.NormalizeVersion()
	var validVersionText = regexp.MustCompile(`(?i)(?:rc|alpha|beta|preview)\d*`)

	for _, k := range maps.Keys(normalizedTags) {
		// "1.8.0-RC0" shouldn't be considered a fuzzy match for "1.8.0"
		if strings.HasPrefix(k, normalizedVersion) && !validVersionText.MatchString(k) {
			candidateTags = append(candidateTags, k)
		}
	}

	// There are zero, one or more tags to further examine for a best choice.

	// Nothing even looked like it started with normalizedVersion, fail.
	if len(candidateTags) == 0 {
		return ac, false
	}

	if len(candidateTags) == 1 {
		ac.SetRepo(repo)
		switch commitType {
		case cves.Introduced:
			ac.SetIntroduced(normalizedTags[candidateTags[0]].Commit)
		case cves.LastAffected:
			ac.SetLastAffected(normalizedTags[candidateTags[0]].Commit)
		case cves.Limit:
			ac.SetLimit(normalizedTags[candidateTags[0]].Commit)
		case cves.Fixed:
			ac.SetFixed(normalizedTags[candidateTags[0]].Commit)
		}
		return ac, true
	}

	for i, t := range candidateTags {
		// Handle the case where where the
		// normalizedVersion is "12-0" (i.e. was "12.0") but the normalizedTags
		// has "12-0-0" (i.e. the repo had "12.0.0")
		if strings.TrimPrefix(t, normalizedVersion) == "-0" {
			ac.SetRepo(repo)
			switch commitType {
			case cves.Introduced:
				ac.SetIntroduced(normalizedTags[candidateTags[i]].Commit)
			case cves.LastAffected:
				ac.SetLastAffected(normalizedTags[candidateTags[i]].Commit)
			case cves.Limit:
				ac.SetLimit(normalizedTags[candidateTags[i]].Commit)
			case cves.Fixed:
				ac.SetFixed(normalizedTags[candidateTags[i]].Commit)
			}
			return ac, true
		}
	}

	// All fuzzy matching attempts have failed.
	return ac, false
}

// Take an unnormalized version string, a repo, the pre-normalized mapping of tags to commits and return an AffectedCommit.
func VersionToCommit(version string, repo string, commitType cves.CommitType, normalizedTags map[string]NormalizedTag) (ac cves.AffectedCommit, e error) {
	normalizedVersion, err := cves.NormalizeVersion(version)
	if err != nil {
		return ac, err
	}
	// Try a straight out match first.
	normalizedTag, ok := normalizedTags[normalizedVersion]
	if !ok {
		// Then try to fuzzy-match.
		ac, ok = fuzzyVersionToCommit(normalizedVersion, repo, commitType, normalizedTags)
		if !ok {
			return ac, fmt.Errorf("failed to find a commit for version %q normalized as %q in %+v", version, normalizedVersion, normalizedTags)
		}
		return ac, nil
	}
	ac.SetRepo(repo)
	switch commitType {
	case cves.Introduced:
		ac.SetIntroduced(normalizedTag.Commit)
	case cves.LastAffected:
		ac.SetLastAffected(normalizedTag.Commit)
	case cves.Limit:
		ac.SetLimit(normalizedTag.Commit)
	case cves.Fixed:
		ac.SetFixed(normalizedTag.Commit)
	}
	return ac, nil
}
