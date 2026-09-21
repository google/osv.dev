package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
)

// VersionTextExtractionStrategy handles natural text version patterns.
//
// Example CVE Record:
//
//	{
//	    "version": "Fixed in version 2.4.1 and higher",
//	    "status": "affected"
//	}
type VersionTextExtractionStrategy struct{}

func (s *VersionTextExtractionStrategy) Name() string {
	return "VersionTextExtraction"
}

func (s *VersionTextExtractionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	possibleVersions := c.ExtractVersionsFromText(nil, vers.Version, metrics, models.VersionSourceAffected)
	if possibleVersions != nil {
		metrics.AddNote("Versions retrieved from text but not used CURRENTLY")
	}

	return nil, VersionRangeTypeUnknown, false
}
