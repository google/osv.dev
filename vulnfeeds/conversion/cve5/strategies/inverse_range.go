package strategies

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// InverseAffectedRangesStrategy calculates affected version ranges by analyzing a list
// of 'unaffected' versions when DefaultStatus == "affected".
// This is common in Linux kernel CVEs where a product is considered affected by default,
// and only unaffected versions are listed.
type InverseAffectedRangesStrategy struct{}

func (s *InverseAffectedRangesStrategy) Name() string {
	return "InverseAffectedRanges"
}

func (s *InverseAffectedRangesStrategy) Extract(state *ExtractionState, metrics *models.ConversionMetrics) {
	if state.Affected.DefaultStatus != "affected" {
		return
	}

	ranges, _ := FindInverseAffectedRanges(state.Affected, metrics)
	if len(ranges) == 0 {
		return
	}

	state.EmitAll(c.ToRangeWithMetadata(ranges, models.VersionSourceAffected))
}

type unaffectedBranchEntry struct {
	fixed          string
	branchKey      string
	nextIntroduced string
}

// normalizeSemverParts normalizes 2-, 3-, or 4-part numeric kernel versions
// (padding 2-part "X.Y" to "X.Y.0").
func normalizeSemverParts(version string) (string, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		if n, err := strconv.Atoi(p); err != nil || n < 0 {
			return "", false
		}
	}
	if len(parts) == 2 {
		return version + ".0", true
	}

	return version, true
}

// FindInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. It pairs each sorted unaffected branch endpoint with the
// preceding branch boundary so explicit mainline 'affected' entries or duplicate fixes on
// the same stable branch do not shift subsequent branch intervals.
func FindInverseAffectedRanges(cveAff models.Affected, metrics *models.ConversionMetrics) (ranges []*osvschema.Range, versType VersionRangeType) {
	var minAffected string
	var entries []unaffectedBranchEntry
	byBranchKey := make(map[string]int)

	for _, vers := range cveAff.Versions {
		versionValue := vers.Version
		if vers.Status == "affected" {
			normalized, ok := normalizeSemverParts(versionValue)
			if !ok {
				metrics.AddNotef("Bad non-semver version given: %s", versionValue)
				continue
			}
			if minAffected == "" || CompareSemverLike(normalized, minAffected) < 0 {
				minAffected = normalized
			}

			continue
		}
		if vers.Status != "unaffected" {
			continue
		}

		if versionValue == "0" || (ToVersionRangeType(vers.VersionType) != VersionRangeTypeSemver && (cveAff.DefaultStatus != "affected" || vers.LessThan != "*")) {
			continue
		}

		var branchKey, nextIntroduced string
		// Infer the next introduced version from the 'lessThanOrEqual' field when a wildcard is present.
		// For example, if "5.10.*" is unaffected, the next introduced version is "5.11.0".
		if minorVers, _, hasWildcard := strings.Cut(vers.LessThanOrEqual, ".*"); hasWildcard {
			branchKey = "wildcard:" + minorVers
			parts := strings.Split(minorVers, ".")
			if len(parts) > 1 {
				if intMin, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
					prefix := strings.Join(parts[:len(parts)-1], ".")
					nextIntroduced = fmt.Sprintf("%s.%d.0", prefix, intMin+1)
				}
			}
		} else if vers.LessThan != "" && vers.LessThan != "*" {
			if normNext, ok := normalizeSemverParts(vers.LessThan); ok {
				branchKey = "lt:" + normNext
				nextIntroduced = normNext
			}
		}

		entry := unaffectedBranchEntry{
			fixed:          versionValue,
			branchKey:      branchKey,
			nextIntroduced: nextIntroduced,
		}
		if branchKey != "" {
			if idx, exists := byBranchKey[branchKey]; exists {
				// Multiple unaffected commits on the same stable branch (e.g. multi-part fixes):
				// the branch is only unaffected once the latest fix version is reached.
				if CompareSemverLike(entry.fixed, entries[idx].fixed) > 0 {
					entries[idx] = entry
				}

				continue
			}
			byBranchKey[branchKey] = len(entries)
		}
		entries = append(entries, entry)
	}

	slices.SortFunc(entries, func(a, b unaffectedBranchEntry) int {
		return CompareSemverLike(a.fixed, b.fixed)
	})

	var currentIntro string
	if len(entries) > 0 {
		switch {
		case minAffected != "":
			if CompareSemverLike(entries[0].fixed, minAffected) < 0 {
				currentIntro = "0"
			} else {
				currentIntro = minAffected
			}
		case cveAff.DefaultStatus == "affected":
			currentIntro = "0"
		}
	}

	for _, entry := range entries {
		if currentIntro != "" && CompareSemverLike(currentIntro, entry.fixed) < 0 {
			ranges = append(ranges, c.BuildVersionRange(currentIntro, "", entry.fixed))
			metrics.AddNotef("Introduced from version value - %s", currentIntro)
			metrics.AddNotef("Fixed from version value - %s", entry.fixed)
		}
		currentIntro = entry.nextIntroduced
	}

	if len(ranges) != 0 {
		return ranges, VersionRangeTypeSemver
	}
	metrics.AddNotef("no ranges found")

	return nil, VersionRangeTypeUnknown
}
