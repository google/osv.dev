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

func (s *ChangesAtStrategy) Extract(state *ExtractionState, metrics *models.ConversionMetrics) {
	ExtractPerVersion(state, metrics, s.extractVersion)
}

func (s *ChangesAtStrategy) extractVersion(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, bool) {
	if vers.Status != "affected" {
		return nil, false
	}

	var fixedFromChanges string
	for _, ch := range vers.Changes {
		if ch.Status == "unaffected" && ch.At != "" {
			fixedFromChanges = ch.At
			break
		}
	}

	if fixedFromChanges == "" {
		return nil, false
	}

	metrics.AddNotef("Fixed from changes - %s", fixedFromChanges)
	var introduced string
	if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		introduced = vers.Version
		metrics.AddNotef("Introduced from version value - %s", vers.Version)
	}

	vr := []*osvschema.Range{c.BuildVersionRange(introduced, "", fixedFromChanges)}

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), true
}
