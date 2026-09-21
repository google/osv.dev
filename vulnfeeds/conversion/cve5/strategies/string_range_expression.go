package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// StringRangeExpressionStrategy handles range expressions embedded within the version field.
//
// Example CVE Record (CVE-2024-21634 - Puma / GitHub_M):
//
//	{
//	    "version": ">= 2.0, < 2.5",
//	    "status": "affected",
//	    "versionType": "semver"
//	}
//
// Resulting OSV Range: [introduced: "2.0", fixed: "2.5"]
type StringRangeExpressionStrategy struct{}

func (s *StringRangeExpressionStrategy) Name() string {
	return "StringRangeExpression"
}

func (s *StringRangeExpressionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	av, err := git.ParseVersionRange(vers.Version)
	if err != nil || av.Introduced == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	currentVersionType := ToVersionRangeType(vers.VersionType)
	var vr []*osvschema.Range
	if av.Fixed != "" {
		vr = append(vr, c.BuildVersionRange(av.Introduced, "", av.Fixed))
	} else if av.LastAffected != "" {
		vr = append(vr, c.BuildVersionRange(av.Introduced, av.LastAffected, ""))
	}

	if len(vr) == 0 {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNotef("Parsed range expression from version: %s", vers.Version)

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}
