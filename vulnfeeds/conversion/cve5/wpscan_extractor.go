package cve5

import (
	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// WPScanVersionExtractor provides version extraction logic for WPScan CVEs.
type WPScanVersionExtractor struct {
	DefaultVersionExtractor
}

var _ VersionExtractor = &WPScanVersionExtractor{}

// ExtractVersions for WPScanVersionExtractor.
func (w *WPScanVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string) {
	// 1. Run default extraction first
	w.DefaultVersionExtractor.ExtractVersions(cve, v, metrics, repos)

	// 2. Extract slug and determine ecosystem using shared helper
	slug, ecosystem := extractWordPressSlugAndEcosystem(cve, v)

	if slug == "" {
		metrics.AddNote("Could not extract slug for WPScan record")
		// We might still want to assign the ecosystem if we can determine it
	}

	// 3. Update affected packages with correct ecosystem and slug
	if len(v.Affected) > 0 {
		for _, aff := range v.Affected {
			isGit := false
			for _, r := range aff.Ranges {
				if r.Type == osvschema.Range_GIT {
					isGit = true
					break
				}
			}
			if isGit {
				continue
			}

			if aff.Package == nil {
				aff.Package = &osvschema.Package{
					Ecosystem: ecosystem,
					Name:      slug,
				}
			} else {
				// Update ecosystem if it was generic
				if aff.Package.Ecosystem == "WordPress" || aff.Package.Ecosystem == "" {
					aff.Package.Ecosystem = ecosystem
				}
				if aff.Package.Name == "" {
					aff.Package.Name = slug
				}
			}
		}
	}

	// 4. If default extraction didn't produce anything, try to generate ECOSYSTEM ranges.
	if len(v.Affected) == 0 {
		metrics.AddNote("Attempting to generate ECOSYSTEM ranges for WPScan")

		gotVersions := false
		var allRanges []*osvschema.Range

		for _, cveAff := range cve.Containers.CNA.Affected {
			versionRanges, _ := w.FindNormalAffectedRanges(cveAff, metrics)
			for _, r := range versionRanges {
				r.Range.Type = osvschema.Range_ECOSYSTEM
				allRanges = append(allRanges, r.Range)
			}
		}

		if len(allRanges) > 0 {
			gotVersions = true
			metrics.AddSource(models.VersionSourceAffected)
		}

		// Description Fallback
		if !gotVersions {
			textRanges := c.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Containers.CNA.Descriptions), metrics, models.VersionSourceDescription)
			for _, r := range textRanges {
				r.Range.Type = osvschema.Range_ECOSYSTEM
				allRanges = append(allRanges, r.Range)
			}
			if len(allRanges) > 0 {
				gotVersions = true
			}
		}

		if gotVersions {
			aff := &osvschema.Affected{
				Package: &osvschema.Package{
					Ecosystem: ecosystem,
					Name:      slug,
				},
				Ranges: allRanges,
			}
			c.AddAffected(v, aff, metrics)
			metrics.Outcome = models.Successful
		}
	}
}
