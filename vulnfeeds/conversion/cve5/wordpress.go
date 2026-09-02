package cve5

import (
	"net/http"
	"regexp"
	"slices"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var (
	wpPluginTracRegex    = regexp.MustCompile(`plugins\.trac\.wordpress\.org/browser/([^/]+)`)
	wpPluginSvnRegex     = regexp.MustCompile(`plugins\.svn\.wordpress\.org/([^/]+)`)
	wordfencePluginRegex = regexp.MustCompile(`wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins/([^/]+)`)
	wpPluginOrgRegex     = regexp.MustCompile(`wordpress\.org/plugins/([^/]+)`)
	wpThemeOrgRegex      = regexp.MustCompile(`wordpress\.org/themes/([^/]+)`)

	patchstackVulnRegex   = regexp.MustCompile(`patchstack\.com/database/vulnerability/([^/]+)`)
	patchstackPluginRegex = regexp.MustCompile(`patchstack\.com/database/wordpress/plugin/([^/]+)`)
	patchstackThemeRegex  = regexp.MustCompile(`patchstack\.com/database/wordpress/theme/([^/]+)`)
)

// extractWordPressSlugAndEcosystem unifies the logic to extract the slug and determine
// the specific WordPress ecosystem (Core, Plugin, Theme) for a given CVE.
func extractWordPressSlugAndEcosystem(cve models.CVE5, v *vulns.Vulnerability) (string, string) {
	var slug string
	var ecosystem string = "WordPress" // Default/Fallback

	// 1. Core Check (Highest Priority)
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		if strings.EqualFold(aff.Vendor, "wordpress") && strings.EqualFold(aff.Product, "wordpress") {
			return "wordpress", "WordPress:Core"
		}
	}

	// 2. Slug from PackageName
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		if aff.PackageName != "" {
			slug = aff.PackageName
		}
	}

	// 3. Ecosystem Extraction from CollectionURL
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		switch aff.CollectionURL {
		case "https://wordpress.org/themes":
			ecosystem = "WordPress:Theme"
		case "https://wordpress.org/plugins":
			ecosystem = "WordPress:Plugin"
		}
	}

	// 4. URL Heuristics Fallback (for slug and ecosystem)
	var tracSlug, svnSlug, wordfenceSlug, wpOrgPluginSlug, wpOrgThemeSlug, patchstackPluginSlug, patchstackThemeSlug, patchstackVulnSlug string
	var urlEcosystem string

	for _, ref := range v.References {
		url := ref.GetUrl()

		if match := wpPluginTracRegex.FindStringSubmatch(url); match != nil {
			tracSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := wpPluginSvnRegex.FindStringSubmatch(url); match != nil {
			svnSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := wordfencePluginRegex.FindStringSubmatch(url); match != nil {
			wordfenceSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := wpPluginOrgRegex.FindStringSubmatch(url); match != nil {
			wpOrgPluginSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := wpThemeOrgRegex.FindStringSubmatch(url); match != nil {
			wpOrgThemeSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Theme"
			}
		} else if match := patchstackPluginRegex.FindStringSubmatch(url); match != nil {
			patchstackPluginSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := patchstackThemeRegex.FindStringSubmatch(url); match != nil {
			patchstackThemeSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Theme"
			}
		} else if match := patchstackVulnRegex.FindStringSubmatch(url); match != nil {
			patchstackVulnSlug = match[1]
		}

		// Generic URL keyword check for ecosystem if still generic
		if urlEcosystem == "" {
			if strings.Contains(url, "/theme/") || strings.Contains(url, "/themes/") {
				urlEcosystem = "WordPress:Theme"
			} else if strings.Contains(url, "/plugin/") || strings.Contains(url, "/plugins/") {
				urlEcosystem = "WordPress:Plugin"
			}
		}
	}

	var urlSlug string
	slugsToTry := []string{
		tracSlug,
		svnSlug,
		wordfenceSlug,
		wpOrgPluginSlug,
		wpOrgThemeSlug,
		patchstackPluginSlug,
		patchstackThemeSlug,
		patchstackVulnSlug,
	}

	for _, s := range slugsToTry {
		if s != "" {
			urlSlug = s
			break
		}
	}

	if slug == "" && urlSlug != "" {
		slug = urlSlug
	}

	// Slug from Product Fallback
	if slug == "" && len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		if vulns.CheckQuality(aff.Product).AtLeast(vulns.Spaces) {
			// Basic slugification (lowercase, replace spaces with hyphens)
			slug = strings.ToLower(aff.Product)
			slug = strings.ReplaceAll(slug, " ", "-")
		}
	}

	if ecosystem == "WordPress" && urlEcosystem != "" {
		ecosystem = urlEcosystem
	}

	// 5. Description/Title Heuristics Fallback
	if ecosystem == "WordPress" {
		desc := strings.ToLower(models.EnglishDescription(cve.Containers.CNA.Descriptions))
		title := strings.ToLower(cve.Containers.CNA.Title)

		if strings.Contains(desc, "plugin") || strings.Contains(title, "plugin") {
			ecosystem = "WordPress:Plugin"
		} else if strings.Contains(desc, "theme") || strings.Contains(title, "theme") {
			ecosystem = "WordPress:Theme"
		}
	}

	return slug, ecosystem
}

// WordpressHandler defines hooks for CNA-specific logic.
type WordpressHandler interface {
	PreExtract(cve *models.CVE5)
	PostExtractDefault(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string)
}

// WordpressExtractor handles version extraction for WordPress CVEs.
type WordpressExtractor struct {
	DefaultVersionExtractor
	Handler WordpressHandler
}

var _ VersionExtractor = &WordpressExtractor{}

func (w *WordpressExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client) {
	if w.Handler != nil {
		w.Handler.PreExtract(&cve)
	}

	// 1. Run default extraction first
	w.DefaultVersionExtractor.ExtractVersions(cve, v, metrics, repos, cache, httpClient)

	// 2. Extract slug and determine ecosystem using shared helper
	slug, ecosystem := extractWordPressSlugAndEcosystem(cve, v)

	if w.Handler != nil {
		w.Handler.PostExtractDefault(cve, v, metrics, slug, ecosystem)
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
				aff.Package = nil // Do not put package info on GIT ranges
				continue
			}

			if slug == "" {
				continue // Skip enriching if we have no slug
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

	// 4. Unified Fallback Strategy
	if len(v.Affected) == 0 {
		if slug == "" {
			metrics.AddNote("Failed to extract versions via default, and no WordPress slug found to attempt fallback")
			return
		}

		metrics.AddNote("Attempting to generate ECOSYSTEM ranges for WordPress")

		gotVersions := false
		var allRanges []*osvschema.Range

		// Fallback 1: CNA Affected
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

		// Fallback 2: CPE
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

		// Fallback 3: Description
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

// DefaultWordpressHandler provides empty implementations for the hooks.
type DefaultWordpressHandler struct{}

func (d *DefaultWordpressHandler) PreExtract(cve *models.CVE5) {}
func (d *DefaultWordpressHandler) PostExtractDefault(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string) {
}

// WordfenceHandler implements Wordfence specific quirks.
type WordfenceHandler struct {
	DefaultWordpressHandler
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

func (w *WordfenceHandler) PreExtract(cve *models.CVE5) {
	for i := range cve.Containers.CNA.Affected {
		for j := range cve.Containers.CNA.Affected[i].Versions {
			vers := &cve.Containers.CNA.Affected[i].Versions[j]
			vers.Version = normalizeVersion(vers.Version)
			vers.LessThan = normalizeVersion(vers.LessThan)
			vers.LessThanOrEqual = normalizeVersion(vers.LessThanOrEqual)
		}
	}
}

// PatchstackHandler implements Patchstack specific quirks.
type PatchstackHandler struct {
	DefaultWordpressHandler
}

func (p *PatchstackHandler) PostExtractDefault(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string) {
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
	}
}

// WPScanHandler implements WPScan specific quirks.
type WPScanHandler struct {
	DefaultWordpressHandler
}
