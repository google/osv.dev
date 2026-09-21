package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// StandardRangeStrategy handles standard CVE 5.0 'lessThan' and 'lessThanOrEqual' range fields.
//
// Example CVE Record (CVE-2026-22104 - Hashtopolis):
//
//	{
//	    "version": "0",
//	    "lessThan": "0.14.8",
//	    "status": "affected",
//	    "versionType": "semver"
//	}
//
// Resulting OSV Range: [introduced: "0", fixed: "0.14.8"]
type StandardRangeStrategy struct{}

func (s *StandardRangeStrategy) Name() string {
	return "StandardRange"
}

func (s *StandardRangeStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	currentVersionType := ToVersionRangeType(vers.VersionType)

	vQuality := vulns.CheckQuality(vers.Version)
	if !vQuality.AtLeast(acceptableQuality) {
		metrics.AddNotef("Version value is filler or empty")
	}
	vLessThanQual := vulns.CheckQuality(vers.LessThan)
	vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

	hasRange := vLessThanQual.AtLeast(acceptableQuality) || vLTOEQual.AtLeast(acceptableQuality)

	// Handle cases where 'lessThan' or 'lessThanOrEqual' is mistakenly the same as 'version'.
	if vers.LessThan != "" && vers.LessThan == vers.Version {
		metrics.AddNotef("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version)
		hasRange = false
	}
	if vers.LessThanOrEqual != "" && vers.LessThanOrEqual == vers.Version {
		metrics.AddNotef("Warning: lessThanOrEqual (%s) is the same as introduced (%s)\n", vers.LessThanOrEqual, vers.Version)
		hasRange = false
	}

	if !hasRange {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNotef("Range detected: %v", hasRange)
	var introduced, fixed, lastaffected string
	if vQuality.AtLeast(acceptableQuality) {
		introduced = vers.Version
		metrics.AddNotef("%s - Introduced from version value - %s", vQuality.String(), vers.Version)
	}

	if vLessThanQual.AtLeast(acceptableQuality) {
		fixed = vers.LessThan
		metrics.AddNotef("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan)
	} else if vLTOEQual.AtLeast(acceptableQuality) {
		lastaffected = vers.LessThanOrEqual
		metrics.AddNotef("%s - LastAffected from LessThanOrEqual value - %s", vLTOEQual.String(), vers.LessThanOrEqual)
	}

	var versionRanges []*osvschema.Range
	if fixed != "" {
		versionRanges = append(versionRanges, c.BuildVersionRange(introduced, "", fixed))
	} else if lastaffected != "" {
		versionRanges = append(versionRanges, c.BuildVersionRange(introduced, lastaffected, ""))
	}

	if len(versionRanges) == 0 {
		return nil, VersionRangeTypeUnknown, false
	}

	for _, vr := range versionRanges {
		if currentVersionType == VersionRangeTypeGit {
			vr.Type = osvschema.Range_GIT
			if affected.Repo != "" {
				vr.Repo = affected.Repo
			}
		}
	}

	return c.ToRangeWithMetadata(versionRanges, models.VersionSourceAffected), currentVersionType, true
}
