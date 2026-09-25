// Copyright 2026 Google LLC
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

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConvertAdvisoryToOSV converts a repository-level GHSA advisory into an OSV Vulnerability record
// with GIT range types resolved against the repository's git tags.
func ConvertAdvisoryToOSV(advisory GHSAAdvisory, repoTarget RepoTarget, normalizedTags map[string]git.NormalizedTag) (*vulns.Vulnerability, error) {
	if advisory.GHSAID == "" {
		return nil, errors.New("advisory GHSA ID is empty")
	}
	if repoTarget.CanonicalURL == "" && repoTarget.Owner != "" && repoTarget.Repo != "" {
		repoTarget.CanonicalURL = fmt.Sprintf("https://github.com/%s/%s", repoTarget.Owner, repoTarget.Repo)
	}

	pubTime := time.Unix(0, 0).UTC()
	if advisory.PublishedAt != nil {
		pubTime = *advisory.PublishedAt
	} else if advisory.CreatedAt != nil {
		pubTime = *advisory.CreatedAt
	}

	modTime := pubTime
	if advisory.UpdatedAt != nil {
		modTime = *advisory.UpdatedAt
	}

	var withdrawnTime *timestamppb.Timestamp
	if advisory.WithdrawnAt != nil {
		withdrawnTime = timestamppb.New(*advisory.WithdrawnAt)
	} else if advisory.State == "withdrawn" {
		withdrawnTime = timestamppb.New(modTime)
	}

	// Build aliases and related lists
	var aliases []string
	if advisory.CVEID != nil && *advisory.CVEID != "" {
		aliases = append(aliases, *advisory.CVEID)
	}
	for _, ident := range advisory.Identifiers {
		if ident.Type == "CVE" && ident.Value != "" {
			aliases = append(aliases, ident.Value)
		}
	}
	aliases = vulns.Unique(aliases)

	// Build severity list
	var severities []*osvschema.Severity
	if advisory.CVSSSeverities != nil {
		if advisory.CVSSSeverities.CVSSV3 != nil && advisory.CVSSSeverities.CVSSV3.VectorString != nil && *advisory.CVSSSeverities.CVSSV3.VectorString != "" {
			severities = append(severities, &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: *advisory.CVSSSeverities.CVSSV3.VectorString,
			})
		}
		if advisory.CVSSSeverities.CVSSV4 != nil && advisory.CVSSSeverities.CVSSV4.VectorString != nil && *advisory.CVSSSeverities.CVSSV4.VectorString != "" {
			severities = append(severities, &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V4,
				Score: *advisory.CVSSSeverities.CVSSV4.VectorString,
			})
		}
	}

	// Collect and classify references
	rawRefs := []models.Reference{
		{URL: advisory.HTMLURL, Tags: []string{"advisory"}},
		{URL: repoTarget.CanonicalURL, Tags: []string{"package"}},
	}
	if advisory.CVEID != nil && *advisory.CVEID != "" {
		rawRefs = append(rawRefs, models.Reference{
			URL:  "https://nvd.nist.gov/vuln/detail/" + *advisory.CVEID,
			Tags: []string{"advisory"},
		})
	}
	if advisory.Description != nil {
		for _, u := range extractURLs(*advisory.Description) {
			rawRefs = append(rawRefs, models.Reference{URL: u})
		}
	}
	references := vulns.ClassifyReferences(rawRefs)

	// Process affected items and resolve version ranges to Git commits
	affectedList, unresolvedRanges := buildAffectedList(advisory, repoTarget, normalizedTags)

	// Build database_specific map
	dbSpecificMap := map[string]any{
		"github_reviewed": false,
	}
	cweIDs := collectCWEs(advisory)
	if len(cweIDs) > 0 {
		dbSpecificMap["cwe_ids"] = cweIDs
	}
	if advisory.Severity != nil && *advisory.Severity != "" {
		dbSpecificMap["severity"] = strings.ToUpper(*advisory.Severity)
	}
	if advisory.URL != "" {
		dbSpecificMap["url"] = advisory.URL
	}
	if len(unresolvedRanges) > 0 {
		dbSpecificMap["unresolved_ranges"] = unresolvedRanges
	}
	dbSpecificStruct, err := utility.NewStructpbFromMap(dbSpecificMap)
	if err != nil {
		logger.Warn("Failed to construct database_specific structpb", slog.String("id", advisory.GHSAID), slog.Any("error", err))
	}

	v := &vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{
			SchemaVersion:    osvconstants.SchemaVersion,
			Id:               advisory.GHSAID,
			Summary:          advisory.Summary,
			Details:          derefString(advisory.Description),
			Aliases:          aliases,
			Published:        timestamppb.New(pubTime),
			Modified:         timestamppb.New(modTime),
			Withdrawn:        withdrawnTime,
			Severity:         severities,
			Affected:         affectedList,
			References:       references,
			DatabaseSpecific: dbSpecificStruct,
		},
	}

	return v, nil
}

// toExtractedEvents converts an AffectedVersion into a slice of raw version osvschema.Event objects,
// mirroring the behavior of vulnfeeds CVE conversion.
func toExtractedEvents(av models.AffectedVersion) []*osvschema.Event {
	var events []*osvschema.Event
	intro := av.Introduced
	if intro == "" {
		intro = "0"
	}
	events = append(events, &osvschema.Event{Introduced: intro})
	if av.Fixed != "" {
		events = append(events, &osvschema.Event{Fixed: av.Fixed})
	} else if av.LastAffected != "" {
		events = append(events, &osvschema.Event{LastAffected: av.LastAffected})
	}

	return events
}

// buildAffectedList processes each vulnerability item in the advisory, resolving version ranges to Git commits.
// Package and ecosystem fields are omitted as repository-specific advisories represent Git repository records.
// Returns the affected list and any unresolved range records for top-level database_specific.
func buildAffectedList(advisory GHSAAdvisory, repoTarget RepoTarget, normalizedTags map[string]git.NormalizedTag) ([]*osvschema.Affected, []map[string]any) {
	var gitRanges []*osvschema.Range
	var unresolvedRanges []map[string]any
	var allParsedRanges []models.AffectedVersion

	for _, vuln := range advisory.Vulnerabilities {
		vRangeStr := derefString(vuln.VulnerableVersionRange)
		patchedVersionsStr := derefString(vuln.PatchedVersions)

		parsedRanges := ParseAdvisoryVersionRanges(vRangeStr, patchedVersionsStr)
		allParsedRanges = append(allParsedRanges, parsedRanges...)

		for _, pr := range parsedRanges {
			gitRange := resolveRangeToGit(pr, repoTarget.CanonicalURL, normalizedTags, advisory.GHSAID)
			if gitRange != nil {
				gitRanges = append(gitRanges, gitRange)
			} else {
				unresolvedRanges = append(unresolvedRanges, map[string]any{
					"extracted_events": toExtractedEvents(pr),
					"source":           string(models.VersionSourceAffected),
				})
			}
		}
	}

	// If no git ranges could be resolved, fall back to default Range_GIT introduced at dawn of time ("0")
	if len(gitRanges) == 0 {
		fallbackRange := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoTarget.CanonicalURL,
			Events: []*osvschema.Event{
				{Introduced: "0"},
			},
		}
		fallbackEvents := make([]*osvschema.Event, 0, len(allParsedRanges)*2)
		for _, pr := range allParsedRanges {
			fallbackEvents = append(fallbackEvents, toExtractedEvents(pr)...)
		}
		if len(fallbackEvents) > 0 {
			dbSpecificMap := map[string]any{
				"extracted_events": fallbackEvents,
				"source":           string(models.VersionSourceAffected),
			}
			if dbSpecific, err := utility.NewStructpbFromMap(dbSpecificMap); err == nil {
				fallbackRange.DatabaseSpecific = dbSpecific
			}
		}
		gitRanges = append(gitRanges, fallbackRange)
	}

	affectedList := []*osvschema.Affected{
		{
			Ranges: gitRanges,
		},
	}

	// Group and deduplicate ranges (merging database_specific.extracted_events)
	conversion.GroupAffectedRanges(affectedList)

	return affectedList, unresolvedRanges
}

// resolveRangeToGit resolves introduced and fixed/last_affected version strings to commit hashes using normalizedTags.
func resolveRangeToGit(av models.AffectedVersion, repoURL string, normalizedTags map[string]git.NormalizedTag, ghsaID string) *osvschema.Range {
	var (
		introCommit   string
		fixedCommit   string
		lastAffCommit string
		err           error
	)

	// Resolve introduced
	if av.Introduced == "" || av.Introduced == "0" {
		introCommit = "0"
	} else {
		introCommit, err = git.VersionToCommit(av.Introduced, normalizedTags)
		if err != nil {
			logger.Debug("Could not resolve introduced version to commit",
				slog.String("id", ghsaID), slog.String("version", av.Introduced), slog.Any("error", err))
			// Fall back to dawn of time so the vulnerability range still functions if fixed commit is found
			introCommit = "0"
		}
	}

	// Resolve fixed
	if av.Fixed != "" {
		fixedCommit, err = git.VersionToCommit(av.Fixed, normalizedTags)
		if err != nil {
			logger.Debug("Could not resolve fixed version to commit",
				slog.String("id", ghsaID), slog.String("version", av.Fixed), slog.Any("error", err))
		}
	}

	// Resolve last_affected
	if av.LastAffected != "" && fixedCommit == "" {
		lastAffCommit, err = git.VersionToCommit(av.LastAffected, normalizedTags)
		if err != nil {
			logger.Debug("Could not resolve last_affected version to commit",
				slog.String("id", ghsaID), slog.String("version", av.LastAffected), slog.Any("error", err))
		}
	}

	// Only return a GIT range if at least one actual commit boundary was resolved.
	if introCommit == "0" && fixedCommit == "" && lastAffCommit == "" {
		return nil
	}

	gitRange := &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: repoURL,
		Events: []*osvschema.Event{
			{Introduced: introCommit},
		},
	}

	if fixedCommit != "" {
		gitRange.Events = append(gitRange.Events, &osvschema.Event{Fixed: fixedCommit})
	} else if lastAffCommit != "" {
		gitRange.Events = append(gitRange.Events, &osvschema.Event{LastAffected: lastAffCommit})
	}

	extractedEvents := toExtractedEvents(av)
	if len(extractedEvents) > 0 {
		dbSpecificMap := map[string]any{
			"extracted_events": extractedEvents,
			"source":           string(models.VersionSourceAffected),
		}
		if dbSpecific, err := utility.NewStructpbFromMap(dbSpecificMap); err == nil {
			gitRange.DatabaseSpecific = dbSpecific
		} else {
			logger.Warn("Failed to create database_specific for git range", slog.String("id", ghsaID), slog.Any("error", err))
		}
	}

	return gitRange
}

// ParseAdvisoryVersionRanges parses version ranges from GHSA fields into models.AffectedVersion slices.
// Handles standard ranges (>= 1.0, < 2.0), single bounds (< 2.0, <= 2.0), exact versions (= 1.0, 1.0),
// compound ranges (< 1.2, >= 2.0, < 2.5), and integrates patched_versions.
func ParseAdvisoryVersionRanges(vRange string, patchedVersions string) []models.AffectedVersion {
	vRange = strings.TrimSpace(vRange)
	patchedVersions = strings.TrimSpace(patchedVersions)

	var results []models.AffectedVersion

	if vRange != "" {
		// Split by compound ranges if present (e.g. "< 1.2.0, >= 2.0.0, < 2.1.0")
		subRanges := splitCompoundRanges(vRange)
		for _, sr := range subRanges {
			av, err := parseSingleRange(sr)
			if err == nil {
				results = append(results, av)
			}
		}
	}

	// If no ranges could be parsed from vRange but patchedVersions is available
	if len(results) == 0 && patchedVersions != "" {
		for pv := range strings.SplitSeq(patchedVersions, ",") {
			pv = strings.TrimSpace(pv)
			if pv != "" {
				results = append(results, models.AffectedVersion{
					Introduced: "0",
					Fixed:      pv,
				})
			}
		}
	} else if len(results) > 0 && patchedVersions != "" {
		// Supplement fixed versions if missing in results
		firstPatched := strings.TrimSpace(strings.Split(patchedVersions, ",")[0])
		if firstPatched != "" {
			for i := range results {
				if results[i].Fixed == "" && results[i].LastAffected != "" {
					results[i].Fixed = firstPatched
				}
			}
		}
	}

	return results
}

func parseSingleRange(r string) (models.AffectedVersion, error) {
	r = strings.TrimSpace(r)

	// Try standard parser from git package
	av, err := git.ParseVersionRange(r)
	if err == nil {
		return av, nil
	}

	// Exact version: "= 1.2.3" or "=1.2.3"
	if rest, ok := strings.CutPrefix(r, "="); ok {
		v := strings.TrimSpace(rest)
		if v != "" {
			return models.AffectedVersion{
				Introduced:   v,
				LastAffected: v,
			}, nil
		}
	}

	// Bare version without operator: e.g. "1.2.3" or "v1.2.3"
	if !strings.ContainsAny(r, "<>=~^") {
		return models.AffectedVersion{
			Introduced:   r,
			LastAffected: r,
		}, nil
	}

	return models.AffectedVersion{}, fmt.Errorf("unable to parse version range: %s", r)
}

// splitCompoundRanges splits strings like "< 1.2.0, >= 2.0.0, < 2.1.0" into separate ranges.
func splitCompoundRanges(vRange string) []string {
	// If it doesn't contain a comma, it's a single range
	if !strings.Contains(vRange, ",") {
		return []string{vRange}
	}

	// If it's a standard two-part range (e.g. ">= 1.0.0, < 2.0.0"), keep together
	parts := strings.Split(vRange, ",")
	if len(parts) == 2 {
		p1 := strings.TrimSpace(parts[0])
		p2 := strings.TrimSpace(parts[1])
		if (strings.HasPrefix(p1, ">=") || strings.HasPrefix(p1, ">")) &&
			(strings.HasPrefix(p2, "<=") || strings.HasPrefix(p2, "<")) {
			return []string{vRange}
		}
	}

	// Otherwise, group parts by boundary operators
	var ranges []string
	var currentRange []string

	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if len(currentRange) == 0 {
			currentRange = append(currentRange, trimmed)
			continue
		}

		// If currentRange already has an introduced bound and trimmed has an upper bound, combine
		if (strings.HasPrefix(currentRange[0], ">=") || strings.HasPrefix(currentRange[0], ">")) &&
			(strings.HasPrefix(trimmed, "<=") || strings.HasPrefix(trimmed, "<")) && len(currentRange) == 1 {
			currentRange = append(currentRange, trimmed)
			ranges = append(ranges, strings.Join(currentRange, ", "))
			currentRange = nil
		} else {
			ranges = append(ranges, strings.Join(currentRange, ", "))
			currentRange = []string{trimmed}
		}
	}

	if len(currentRange) > 0 {
		ranges = append(ranges, strings.Join(currentRange, ", "))
	}

	return ranges
}

func collectCWEs(advisory GHSAAdvisory) []string {
	var cwes []string
	cwes = append(cwes, advisory.CWEIDs...)
	for _, cwe := range advisory.CWEs {
		if cwe.CWEID != "" {
			cwes = append(cwes, cwe.CWEID)
		}
	}
	slices.Sort(cwes)

	return slices.Compact(cwes)
}

var urlRegex = regexp.MustCompile(`https?://[^\s)\]>"']+`)

func extractURLs(text string) []string {
	matches := urlRegex.FindAllString(text, -1)
	var validURLs []string
	for _, m := range matches {
		m = strings.TrimRight(m, ".,;:")
		if u, err := url.Parse(m); err == nil && u.Scheme != "" && u.Host != "" {
			validURLs = append(validURLs, m)
		}
	}

	return vulns.Unique(validURLs)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
