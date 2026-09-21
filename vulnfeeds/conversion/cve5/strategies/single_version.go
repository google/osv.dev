package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ZeroIntroducedSingleVersionStrategy treats a single version value (when only 1 version is listed)
// as spanning from 0 to that version (e.g. WPScan, Wordfence, Linux, or single-version MITRE records).
//
// Example CVE Record (CVE-2015-10001 - WPScan / Wordfence / MITRE):
//
//	{
//	    "version": "2.52",
//	    "status": "affected",
//	    "versionType": "custom"
//	}
//
// Resulting OSV Range: [introduced: "0", last_affected: "2.52"]
type ZeroIntroducedSingleVersionStrategy struct{}

func (s *ZeroIntroducedSingleVersionStrategy) Name() string {
	return "ZeroIntroducedSingleVersion"
}

func (s *ZeroIntroducedSingleVersionStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}
	if len(affected.Versions) > 1 {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Single version found %v - Assuming introduced = 0 and last affected = %v", vers.Version, vers.Version)
	currentVersionType := ToVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange("0", vers.Version, "")}

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}

// StandaloneSingleVersionStrategy treats a single version as an exact, standalone version (introduced == last_affected).
//
// Example CVE Record:
//
//	{
//	    "version": "1.0.0",
//	    "status": "affected"
//	}
//
// Resulting OSV Range: [introduced: "1.0.0", last_affected: "1.0.0"]
type StandaloneSingleVersionStrategy struct{}

func (s *StandaloneSingleVersionStrategy) Name() string {
	return "StandaloneSingleVersion"
}

func (s *StandaloneSingleVersionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Single version found %v - Treating as standalone version", vers.Version)
	currentVersionType := ToVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, vers.Version, "")}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceAffected)
	for i := range rwms {
		rwms[i].Metadata.Versions = []string{vers.Version}
	}

	return rwms, currentVersionType, true
}
