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
	"slices"
	"strings"

	"github.com/google/osv/vulnfeeds/models"
	"golang.org/x/exp/maps"
)

var versionRangeRegex = regexp.MustCompile(`^(>=|<=|~|\^|>|<|=)\s*([0-9a-zA-Z\.\-]+)(?:,\s*(>=|<=|~|\^|>|<|=)\s*([0-9a-zA-Z\.\-]+))?$`) // Used to parse version strings from the GitHub CNA.

// Take an already normalized version, repo and the mapping of repo tags
// normalized tags and commits and do fuzzy matching version, returning a
// GitCommit and a bool if successful.
func fuzzyVersionToCommit(normalizedVersion string, repo string, commitType models.CommitType, normalizedTags map[string]NormalizedTag) (ac models.AffectedCommit, b bool) {
	candidateTags := []string{} // the subset of normalizedTags tags that might be appropriate to use as a fuzzy match for normalizedVersion.
	// Keep in sync with the regex in models.NormalizeVersion()
	var validVersionText = regexp.MustCompile(`(?i)(?:rc|alpha|beta|preview)\d*`)

	for _, k := range maps.Keys(normalizedTags) {
		// "1-8-0-RC0" (normalized from "1.8.0-RC0") shouldn't be considered a fuzzy match for "1-8-0" (normalized from "1.8.0")
		if (validVersionText.MatchString(k) && validVersionText.MatchString(normalizedVersion)) && strings.HasPrefix(k, normalizedVersion) {
			candidateTags = append(candidateTags, k)
		}
		if (!validVersionText.MatchString(k) && !validVersionText.MatchString(normalizedVersion)) && strings.HasPrefix(k, normalizedVersion) {
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
		case models.Introduced:
			ac.SetIntroduced(normalizedTags[candidateTags[0]].Commit)
		case models.LastAffected:
			ac.SetLastAffected(normalizedTags[candidateTags[0]].Commit)
		case models.Limit:
			ac.SetLimit(normalizedTags[candidateTags[0]].Commit)
		case models.Fixed:
			ac.SetFixed(normalizedTags[candidateTags[0]].Commit)
		}
		return ac, true
	}

	// Find the most suitable tag from multiple.
	for i, t := range candidateTags {
		// Handle the case where where the
		// normalizedVersion is "12-0" (i.e. was "12.0") but the normalizedTags
		// has "12-0-0" (i.e. the repo had "12.0.0")
		if strings.TrimPrefix(t, normalizedVersion) == "-0" {
			ac.SetRepo(repo)
			switch commitType {
			case models.Introduced:
				ac.SetIntroduced(normalizedTags[candidateTags[i]].Commit)
			case models.LastAffected:
				ac.SetLastAffected(normalizedTags[candidateTags[i]].Commit)
			case models.Limit:
				ac.SetLimit(normalizedTags[candidateTags[i]].Commit)
			case models.Fixed:
				ac.SetFixed(normalizedTags[candidateTags[i]].Commit)
			}
			return ac, true
		}
	}

	// All fuzzy matching attempts have failed.
	return ac, false
}

// Take an unnormalized version string, a repo, the pre-normalized mapping of tags to commits and return an AffectedCommit.
func VersionToCommit(version string, repo string, commitType models.CommitType, normalizedTags map[string]NormalizedTag) (ac models.AffectedCommit, e error) {
	normalizedVersion, err := NormalizeVersion(version)
	if err != nil {
		return ac, err
	}
	// Try a straight out (case-insensitive) match first.
	normalizedTag, ok := normalizedTags[strings.ToLower(normalizedVersion)]
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
	case models.Introduced:
		ac.SetIntroduced(normalizedTag.Commit)
	case models.LastAffected:
		ac.SetLastAffected(normalizedTag.Commit)
	case models.Limit:
		ac.SetLimit(normalizedTag.Commit)
	case models.Fixed:
		ac.SetFixed(normalizedTag.Commit)
	}
	return ac, nil
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

// Parse a version range string into an models.AffectedVersion struct,
// which aligns with the structure used by GitHub CNA feeds.
func ParseVersionRange(versionRange string) (models.AffectedVersion, error) {
	matches := versionRangeRegex.FindStringSubmatch(strings.TrimSpace(versionRange))

	if len(matches) == 0 {
		return models.AffectedVersion{}, fmt.Errorf("invalid version range format: %s", versionRange)
	}

	av := models.AffectedVersion{}

	op1 := matches[1]
	ver1 := matches[2]
	op2 := matches[3]
	ver2 := matches[4]

	if op2 == "" {
		// Only one constraint
		switch op1 {
		case ">=":
			av.Introduced = ver1
		case ">":
			av.Introduced = ver1
		case "<=":
			av.Introduced = "0"
			av.LastAffected = ver1
		case "<":
			av.Introduced = "0"
			av.Fixed = ver1
		default:
			return models.AffectedVersion{}, fmt.Errorf("unhandled single operator: %s", op1)
		}
	} else {
		// Two constraints
		if op1 == ">=" {
			av.Introduced = ver1
		} else {
			return models.AffectedVersion{}, fmt.Errorf("unexpected operator at start of range: %s", op1)
		}

		switch op2 {
		case "<":
			av.Fixed = ver2
		case "<=":
			av.LastAffected = ver2
		default:
			return models.AffectedVersion{}, fmt.Errorf("unexpected operator at end of range: %s", op2)
		}
	}

	return av, nil
}
