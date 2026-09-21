package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ChangesAtStrategy extracts the fixed version from the vers.Changes list when status is 'unaffected'.
//
// Resulting OSV Range: [introduced: "17.7.0", fixed: "17.7.2"]
type ChangesAtStrategy struct{}

func (s *ChangesAtStrategy) Name() string {
	return "ChangesAt"
}

func (s *ChangesAtStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	var fixedFromChanges string
	for _, ch := range vers.Changes {
		if ch.Status == "unaffected" && ch.At != "" {
			fixedFromChanges = ch.At
			break
		}
	}

	if fixedFromChanges == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Fixed from changes - %s", fixedFromChanges)
	var introduced string
	if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		introduced = vers.Version
		metrics.AddNote("Introduced from version value - %s", vers.Version)
	}

	currentVersionType := ToVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(introduced, "", fixedFromChanges)}

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}
