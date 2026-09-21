package strategies

import (
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// SplitRangeStrategy handles split sequential version ranges
// (e.g. one entry with introduced and lessThan="unspecified", followed by an entry
// with version="unspecified" and lessThan/lessThanOrEqual).
//
// Example 1: Split Pair (CVE-2022-25929):
//
//	"versions": [
//	    { "version": "1.31.0", "lessThan": "unspecified", "status": "affected" },
//	    { "version": "unspecified", "lessThan": "1.36.1", "status": "affected" }
//	]
//	Resulting OSV Range: [introduced: "1.31.0", fixed: "1.36.1"]
//
// Example 2: Multi Split Sequences (CVE-2022-25761):
//
//	"versions": [
//	    { "version": "unspecified", "lessThan": "1.2.5", "status": "affected" },
//	    { "version": "1.3-rc1", "lessThan": "unspecified", "status": "affected" },
//	    { "version": "unspecified", "lessThan": "1.3.1", "status": "affected" }
//	]
//	Resulting OSV Ranges: [introduced: "0", fixed: "1.2.5"], [introduced: "1.3-rc1", fixed: "1.3.1"]
//
// Example 3: Standalone Upper Bound (CVE-2022-25865):
//
//	"versions": [
//	    { "version": "unspecified", "lessThan": "0.18.4", "status": "affected" }
//	]
//	Resulting OSV Range: [introduced: "0", fixed: "0.18.4"]
type SplitRangeStrategy struct{}

func (s *SplitRangeStrategy) Name() string {
	return "SplitRange"
}

func isExplicitUnspecified(val string) bool {
	clean := strings.TrimSpace(strings.ToLower(val))

	return clean == "unspecified"
}

func isValidSplitVersion(val string) bool {
	clean := strings.TrimSpace(strings.ToLower(val))
	if clean == "" || clean == "unspecified" || clean == "n/a" || clean == "na" || clean == "*" || clean == "-" {
		return false
	}

	return vulns.CheckQuality(val).AtLeast(acceptableQuality) || val == "0"
}

func isSplitIntroducedOnly(v models.Versions) bool {
	return isValidSplitVersion(v.Version) && (isExplicitUnspecified(v.LessThan) || isExplicitUnspecified(v.LessThanOrEqual))
}

func isSplitUpperBoundOnly(v models.Versions) bool {
	return isExplicitUnspecified(v.Version) && (isValidSplitVersion(v.LessThan) || isValidSplitVersion(v.LessThanOrEqual))
}

func (s *SplitRangeStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	// Check for "unspecified" split or standalone ranges across affected.Versions
	idx := -1
	for i, v := range affected.Versions {
		if v.Version == vers.Version && v.LessThan == vers.LessThan && v.LessThanOrEqual == vers.LessThanOrEqual && v.Status == vers.Status && v.VersionType == vers.VersionType {
			idx = i
			break
		}
	}

	// Case A: Introduced-only entry (e.g. {version: "1.31.0", lessThan: "unspecified"})
	if isSplitIntroducedOnly(vers) {
		currentVersionType := ToVersionRangeType(vers.VersionType)
		// Check if the immediately following entry is an upper-bound entry
		if idx >= 0 && idx+1 < len(affected.Versions) && isSplitUpperBoundOnly(affected.Versions[idx+1]) {
			nextVers := affected.Versions[idx+1]
			var fixed, lastAffected string
			if isValidSplitVersion(nextVers.LessThan) {
				fixed = nextVers.LessThan
			} else if isValidSplitVersion(nextVers.LessThanOrEqual) {
				lastAffected = nextVers.LessThanOrEqual
			}

			vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, lastAffected, fixed)}
			metrics.AddNotef("Parsed split range: introduced %s, upper bound %s%s", vers.Version, fixed, lastAffected)

			return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
		}

		// Standalone introduced entry without a following upper bound
		vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, "", "")}
		metrics.AddNotef("Parsed standalone introduced version: %s", vers.Version)

		return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
	}

	// Case B: Upper-bound-only entry (e.g. {version: "unspecified", lessThan: "1.36.1"})
	if isSplitUpperBoundOnly(vers) {
		currentVersionType := ToVersionRangeType(vers.VersionType)
		// If preceded by an introduced-only entry, it was already paired and consumed in Case A
		if idx > 0 && isSplitIntroducedOnly(affected.Versions[idx-1]) {
			return nil, currentVersionType, true
		}

		// Standalone upper bound starting from 0
		var fixed, lastAffected string
		if isValidSplitVersion(vers.LessThan) {
			fixed = vers.LessThan
		} else if isValidSplitVersion(vers.LessThanOrEqual) {
			lastAffected = vers.LessThanOrEqual
		}

		vr := []*osvschema.Range{c.BuildVersionRange("0", lastAffected, fixed)}
		metrics.AddNotef("Parsed upper-bound range with introduced=0: %s%s", fixed, lastAffected)

		return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
	}

	return nil, VersionRangeTypeUnknown, false
}
