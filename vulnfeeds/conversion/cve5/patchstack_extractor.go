package cve5

import (
	"regexp"
	"strings"

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

var (
	patchstackVulnRegex   = regexp.MustCompile(`patchstack\.com/database/vulnerability/([^/]+)`)
	patchstackPluginRegex = regexp.MustCompile(`patchstack\.com/database/wordpress/plugin/([^/]+)`)
	patchstackThemeRegex  = regexp.MustCompile(`patchstack\.com/database/wordpress/theme/([^/]+)`)
	wpPluginsRegex       = regexp.MustCompile(`wordpress\.org/plugins/([^/]+)`)
	wpThemesRegex        = regexp.MustCompile(`wordpress\.org/themes/([^/]+)`)
)

func extractSlugAndEcosystem(cve models.CVE5, v *vulns.Vulnerability) (string, string) {
	var slug string
	var ecosystem string = "WordPress" // Default/Fallback

	// 1. Try packageName and collectionURL
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		if aff.PackageName != "" {
			slug = aff.PackageName
		}
		if aff.CollectionURL == "https://wordpress.org/themes" {
			ecosystem = "WordPress:Theme"
		} else if aff.CollectionURL == "https://wordpress.org/plugins" {
			ecosystem = "WordPress:Plugin"
		}
	}

	// 2. Fallback to URLs if slug is missing or ecosystem is generic
	if slug == "" || ecosystem == "WordPress" {
		for _, ref := range v.References {
			url := ref.GetUrl()

			if slug == "" {
				if match := patchstackVulnRegex.FindStringSubmatch(url); match != nil {
					slug = match[1]
				} else if match := patchstackPluginRegex.FindStringSubmatch(url); match != nil {
					slug = match[1]
					if ecosystem == "WordPress" {
						ecosystem = "WordPress:Plugin"
					}
				} else if match := patchstackThemeRegex.FindStringSubmatch(url); match != nil {
					slug = match[1]
					if ecosystem == "WordPress" {
						ecosystem = "WordPress:Theme"
					}
				} else if match := wpPluginsRegex.FindStringSubmatch(url); match != nil {
					slug = match[1]
					if ecosystem == "WordPress" {
						ecosystem = "WordPress:Plugin"
					}
				} else if match := wpThemesRegex.FindStringSubmatch(url); match != nil {
					slug = match[1]
					if ecosystem == "WordPress" {
						ecosystem = "WordPress:Theme"
					}
				}
			}

			// If slug already found via packageName, but ecosystem is still generic, try to infer from URLs
			if ecosystem == "WordPress" {
				if strings.Contains(url, "/theme/") || strings.Contains(url, "/themes/") {
					ecosystem = "WordPress:Theme"
				} else if strings.Contains(url, "/plugin/") || strings.Contains(url, "/plugins/") {
					ecosystem = "WordPress:Plugin"
				}
			}
		}
	}

	return slug, ecosystem
}

// ExtractVersions for PatchstackVersionExtractor.
func (p *PatchstackVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string) {
	// 1. Run default extraction first
	p.DefaultVersionExtractor.ExtractVersions(cve, v, metrics, repos)

	// 2. Extract slug and determine ecosystem
	slug, ecosystem := extractSlugAndEcosystem(cve, v)

	if slug == "" {
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
