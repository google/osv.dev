package cve5

import (
	"slices"

	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// PatchstackVersionExtractor provides version extraction logic for Patchstack CVEs.
type PatchstackVersionExtractor struct {
	DefaultVersionExtractor
}

var _ VersionExtractor = &PatchstackVersionExtractor{}

// ExtractVersions for PatchstackVersionExtractor.
func (p *PatchstackVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string) {
	// 1. Run default extraction first
	p.DefaultVersionExtractor.ExtractVersions(cve, v, metrics, repos)

	// 2. Extract slug and determine ecosystem using shared helper
	slug, ecosystem := extractWordPressSlugAndEcosystem(cve, v)

	if slug != "" {
		var baseURL string
		switch ecosystem {
		case "WordPress:Plugin":
			baseURL = "https://wordpress.org/plugins/"
		case "WordPress:Theme":
			baseURL = "https://wordpress.org/themes/"
		}

		if baseURL != "" {
			wpURL := baseURL + slug + "/"
			// Check if already exists to avoid duplicates
			exists := slices.ContainsFunc(v.References, func(ref *osvschema.Reference) bool {
				return ref.GetUrl() == wpURL
			})
			if !exists {
				v.References = append(v.References, &osvschema.Reference{
					Type: osvschema.Reference_WEB,
					Url:  wpURL,
				})
				metrics.AddNote("Added wordpress.org reference link: %s", wpURL)
			}
		}
	} else {
		metrics.AddNote("Could not extract slug for Patchstack record")
		return
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
			}
		}
	}

	// 4. If default extraction didn't produce anything (e.g. no git ranges found),
	// we still want to produce ECOSYSTEM ranges for WordPress.
	// This mirrors Wordfence extractor logic.
	if len(v.Affected) == 0 {
		metrics.AddNote("Attempting to generate ECOSYSTEM ranges for Patchstack")

		gotVersions := false
		var allRanges []*osvschema.Range

		for _, cveAff := range cve.Containers.CNA.Affected {
			versionRanges, _ := p.FindNormalAffectedRanges(cveAff, metrics)
			for _, r := range versionRanges {
				r.Range.Type = osvschema.Range_ECOSYSTEM
				allRanges = append(allRanges, r.Range)
			}
		}

		if len(allRanges) > 0 {
			gotVersions = true
			metrics.AddSource(models.VersionSourceAffected)
		}

		// Description Fallback (if still no versions)
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
			metrics.Outcome = models.Successful // Override outcome directly
		}
	}
}
