package cve5

import (
	"regexp"
	"strings"

	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// WordfenceVersionExtractor provides version extraction logic for Wordfence CVEs.
type WordfenceVersionExtractor struct {
	DefaultVersionExtractor
}

var _ VersionExtractor = &WordfenceVersionExtractor{}

var (
	tracRegex      = regexp.MustCompile(`plugins\.trac\.wordpress\.org/browser/([^/]+)`)
	svnRegex       = regexp.MustCompile(`plugins\.svn\.wordpress\.org/([^/]+)`)
	wordfenceRegex = regexp.MustCompile(`wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins/([^/]+)`)
	wpOrgRegex     = regexp.MustCompile(`wordpress\.org/plugins/([^/]+)`)
)

func extractSlugFromOSVRefs(refs []*osvschema.Reference) string {
	var tracSlug, svnSlug, wordfenceSlug, wpOrgSlug string

	for _, ref := range refs {
		url := ref.GetUrl()
		if match := tracRegex.FindStringSubmatch(url); match != nil {
			tracSlug = match[1]
		}
		if match := svnRegex.FindStringSubmatch(url); match != nil {
			svnSlug = match[1]
		}
		if match := wordfenceRegex.FindStringSubmatch(url); match != nil {
			wordfenceSlug = match[1]
		}
		if match := wpOrgRegex.FindStringSubmatch(url); match != nil {
			wpOrgSlug = match[1]
		}
	}

	// Prioritize trac slug
	if tracSlug != "" {
		return tracSlug
	}
	if svnSlug != "" {
		return svnSlug
	}
	if wordfenceSlug != "" {
		return wordfenceSlug
	}
	if wpOrgSlug != "" {
		return wpOrgSlug
	}

	return ""
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

// ExtractVersions for WordfenceVersionExtractor.
func (w *WordfenceVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string) {
	// Normalize versions in cve first
	for i := range cve.Containers.CNA.Affected {
		for j := range cve.Containers.CNA.Affected[i].Versions {
			vers := &cve.Containers.CNA.Affected[i].Versions[j]
			vers.Version = normalizeVersion(vers.Version)
			vers.LessThan = normalizeVersion(vers.LessThan)
			vers.LessThanOrEqual = normalizeVersion(vers.LessThanOrEqual)
		}
	}

	// 1. Try standard extraction (which prefers GIT ranges)
	w.DefaultVersionExtractor.ExtractVersions(cve, v, metrics, repos)

	slug := extractSlugFromOSVRefs(v.References)

	// 2. If we have Affected entries, update them with slug/ecosystem if missing.
	if len(v.Affected) > 0 {
		if slug != "" {
			for _, aff := range v.Affected {
				isGit := false
				for _, r := range aff.Ranges {
					if r.Type == osvschema.Range_GIT {
						isGit = true
						break
					}
				}
				if isGit {
					aff.Package = nil // Do not put package info on GIT ranges
					continue
				}
				if aff.Package == nil {
					aff.Package = &osvschema.Package{
						Ecosystem: string(osvconstants.EcosystemWordPress),
						Name:      slug,
					}
				}
			}
		}
		// Do not return early, we want both GIT and ECOSYSTEM ranges if they exist.
	}

	// 3. We also want to produce ECOSYSTEM ranges if possible.
	if slug == "" {
		if len(v.Affected) == 0 {
			metrics.AddNote("Failed to extract versions via default, and no WordPress slug found to attempt fallback")
		} else {
			metrics.AddNote("No WordPress slug found to attempt generating ECOSYSTEM ranges")
		}
		return
	}

	metrics.AddNote("Attempting to generate ECOSYSTEM ranges for WordPress")

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

	// CPE Fallback
	if !gotVersions {
		versionRanges, _ := cpeVersionExtraction(cve, metrics)
		for _, r := range versionRanges {
			r.Range.Type = osvschema.Range_ECOSYSTEM
			allRanges = append(allRanges, r.Range)
		}
		if len(allRanges) > 0 {
			gotVersions = true
		}
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
				Ecosystem: string(osvconstants.EcosystemWordPress),
				Name:      slug,
			},
			Ranges: allRanges,
		}
		c.AddAffected(v, aff, metrics)
		metrics.Outcome = models.Successful // Override outcome directly
	}
}
