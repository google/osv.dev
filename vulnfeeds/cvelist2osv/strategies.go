package cvelist2osv

import (
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func cpeVersionExtraction(cve cves.CVE5, metrics *ConversionMetrics) ([]osvschema.Range, error) {
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err == nil && len(cpeRanges) > 0 {
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)

		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNote("%s", err.Error())
	}

	return nil, err
}

// textVersionExtraction is a helper function for CPE and description extraction.
func textVersionExtraction(cve cves.CVE5, metrics *ConversionMetrics) []osvschema.Range {
	// As a last resort, try extracting versions from the description text.
	versions, extractNotes := cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
	for _, note := range extractNotes {
		metrics.AddNote("%s", note)
	}
	if len(versions) > 0 {
		// NOTE: These versions are not currently saved due to the need for better validation.
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceDescription)
		metrics.AddNote("Extracted versions from description but did not save them: %+v", versions)
	}

	return []osvschema.Range{}
}

// initialNormalExtraction handles an expected case of version ranges in the affected field of CVE5
func initialNormalExtraction(vers cves.Versions, metrics *ConversionMetrics, versionTypesCount map[VersionRangeType]int) ([]osvschema.Range, VersionRangeType, bool) {
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
	metrics.AddNote("Range detected: %v", hasRange)
	// Handle cases where 'lessThan' is mistakenly the same as 'version'.
	if vers.LessThan != "" && vers.LessThan == vers.Version {
		metrics.AddNote("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version)
		hasRange = false
	}

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
		var versionRanges []osvschema.Range
		if fixed != "" {
			versionRanges = append(versionRanges, cves.BuildVersionRange(introduced, "", fixed))
		} else if lastaffected != "" {
			versionRanges = append(versionRanges, cves.BuildVersionRange(introduced, lastaffected, ""))
		}

		return versionRanges, currentVersionType, true
	}

	return nil, VersionRangeTypeUnknown, false
}
