package cvelist2osv

import (
	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func cpeVersionExtraction(cve models.CVE5, metrics *models.ConversionMetrics) ([]*osvschema.Range, error) {
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err == nil && len(cpeRanges) > 0 {
		metrics.VersionSources = append(metrics.VersionSources, models.VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)

		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNote("%s", err.Error())
	}

	return nil, err
}

// initialNormalExtraction handles an expected case of version ranges in the affected field of CVE5
func initialNormalExtraction(vers models.Versions, metrics *models.ConversionMetrics, versionTypesCount map[VersionRangeType]int) ([]*osvschema.Range, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, true
	}

	currentVersionType := toVersionRangeType(vers.VersionType)
	versionTypesCount[currentVersionType]++

	var introduced, fixed, lastaffected string

	// Quality check the version strings to avoid using filler content.
	vQuality := vulns.CheckQuality(vers.Version)
	if !vQuality.AtLeast(acceptableQuality) {
		metrics.AddNote("Version value for is filler or empty")
	}
	vLessThanQual := vulns.CheckQuality(vers.LessThan)
	vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

	hasRange := vLessThanQual.AtLeast(acceptableQuality) || vLTOEQual.AtLeast(acceptableQuality)
	
	// Handle cases where 'lessThan' is mistakenly the same as 'version'.
	if vers.LessThan != "" && vers.LessThan == vers.Version {
		metrics.AddNote("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version)
		hasRange = false
	}
	if vers.LessThanOrEqual != "" && vers.LessThanOrEqual == vers.Version {
		metrics.AddNote("Warning: lessThanOrEqual (%s) is the same as introduced (%s)\n", vers.LessThanOrEqual, vers.Version)
		hasRange = false
	}

	metrics.AddNote("Range detected: %v", hasRange)
	if hasRange {
		if vQuality.AtLeast(acceptableQuality) {
			introduced = vers.Version
			metrics.AddNote("%s - Introduced from version value - %s", vQuality.String(), vers.Version)
		}
		if vLessThanQual.AtLeast(acceptableQuality) {
			fixed = vers.LessThan
			metrics.AddNote("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan)
		} else if vLTOEQual.AtLeast(acceptableQuality) {
			lastaffected = vers.LessThanOrEqual
			metrics.AddNote("%s - LastAffected from LessThanOrEqual value- %s", vLTOEQual.String(), vers.LessThanOrEqual)
		}
		var versionRanges []*osvschema.Range
		if fixed != "" {
			versionRanges = append(versionRanges, conversion.BuildVersionRange(introduced, "", fixed))
		} else if lastaffected != "" {
			versionRanges = append(versionRanges, conversion.BuildVersionRange(introduced, lastaffected, ""))
		}

		return versionRanges, currentVersionType, true
	}

	return nil, VersionRangeTypeUnknown, false
}
