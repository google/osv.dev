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

// FindInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. It sorts the introduced and fixed versions to create chronological ranges.
func FindInverseAffectedRanges(cveAff models.Affected, metrics *models.ConversionMetrics) (ranges []*osvschema.Range, versType VersionRangeType) {
	var introduced []string
	fixed := make([]string, 0, len(cveAff.Versions))
	for _, vers := range cveAff.Versions {
		versionValue := vers.Version
		if vers.Status == "affected" {
			numParts := len(strings.Split(versionValue, "."))
			switch numParts {
			case 2:
				introduced = append(introduced, versionValue+".0")
			case 3:
				introduced = append(introduced, versionValue)
			default:
				metrics.AddNotef("Bad non-semver version given: %s", versionValue)
				continue
			}
		}
		if vers.Status != "unaffected" {
			continue
		}

		if versionValue == "0" || (ToVersionRangeType(vers.VersionType) != VersionRangeTypeSemver && (cveAff.DefaultStatus != "affected" || vers.LessThan != "*")) {
			continue
		}
		fixed = append(fixed, versionValue)
		// Infer the next introduced version from the 'lessThanOrEqual' field when a wildcard is present.
		// For example, if "5.10.*" is unaffected, the next introduced version is "5.11.0".
		if minorVers, _, hasWildcard := strings.Cut(vers.LessThanOrEqual, ".*"); hasWildcard {
			parts := strings.Split(minorVers, ".")
			if len(parts) > 1 {
				if intMin, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
					nextIntroduced := fmt.Sprintf("%s.%d.0", parts[0], intMin+1)
					introduced = append(introduced, nextIntroduced)
				}
			}
		}
	}
	slices.SortFunc(introduced, CompareSemverLike)
	slices.SortFunc(fixed, CompareSemverLike)

	// If the first fixed version is earlier than the first introduced (or no introduced was listed while defaultStatus is affected), assume introduction from "0".
	if len(fixed) > 0 && ((len(introduced) == 0 && cveAff.DefaultStatus == "affected") || (len(introduced) > 0 && CompareSemverLike(fixed[0], introduced[0]) < 0)) {
		introduced = append([]string{"0"}, introduced...)
	}

	// Create ranges by pairing sorted introduced and fixed versions.
	for index, f := range fixed {
		if index < len(introduced) {
			ranges = append(ranges, c.BuildVersionRange(introduced[index], "", f))
			metrics.AddNotef("Introduced from version value - %s", introduced[index])
			metrics.AddNotef("Fixed from version value - %s", f)
		}
	}

	if len(ranges) != 0 {
		return ranges, VersionRangeTypeSemver
	}
	metrics.AddNotef("no ranges found")

	return nil, VersionRangeTypeUnknown
}
