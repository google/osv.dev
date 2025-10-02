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

func aiVersionExtraction() {
	// not implemented yet
}
