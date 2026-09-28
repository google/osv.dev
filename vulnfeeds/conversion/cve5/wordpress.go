package cve5

import (
	"net/http"
	"regexp"
	"slices"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var (
	wpPluginTracRegex = regexp.MustCompile(`plugins\.trac\.wordpress\.org/browser/([^/]+)`)
	wpPluginSvnRegex  = regexp.MustCompile(`plugins\.svn\.wordpress\.org/([^/]+)`)
	wpPluginOrgRegex  = regexp.MustCompile(`wordpress\.org/plugins/([^/]+)`)
	wpThemeTracRegex  = regexp.MustCompile(`themes\.trac\.wordpress\.org/browser/([^/]+)`)
	wpThemeSvnRegex   = regexp.MustCompile(`themes\.svn\.wordpress\.org/([^/]+)`)
	wpThemeOrgRegex   = regexp.MustCompile(`wordpress\.org/themes/([^/]+)`)

	wordfencePluginRegex = regexp.MustCompile(`wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins/([^/]+)`)
	wordfenceThemeRegex  = regexp.MustCompile(`wordfence\.com/threat-intel/vulnerabilities/wordpress-themes/([^/]+)`)

	patchstackVulnRegex   = regexp.MustCompile(`patchstack\.com/database/vulnerability/([^/]+)`)
	patchstackPluginRegex = regexp.MustCompile(`patchstack\.com/database/wordpress/plugin/([^/]+)`)
	patchstackThemeRegex  = regexp.MustCompile(`patchstack\.com/database/wordpress/theme/([^/]+)`)
)

// extractWordPressSlugAndEcosystem unifies the logic to extract the slug and determine
// the specific WordPress ecosystem (Core, Plugin, Theme) for a given CVE.
func extractWordPressSlugAndEcosystem(cve models.CVE5, v *vulns.Vulnerability) (string, string) {
	var slug string
	var ecosystem = "WordPress" // Default/Fallback

	// 1. Core Check (Highest Priority)
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		if strings.EqualFold(aff.Vendor, "wordpress") && strings.EqualFold(aff.Product, "wordpress") {
			return "wordpress", "WordPress:Core"
		}
	}

	// 2. Ecosystem Extraction from CollectionURL
	if len(cve.Containers.CNA.Affected) > 0 {
		aff := cve.Containers.CNA.Affected[0]
		switch aff.CollectionURL {
		case "https://wordpress.org/themes":
			ecosystem = "WordPress:Theme"
		case "https://wordpress.org/plugins":
			ecosystem = "WordPress:Plugin"
		}
	}

	// 3. Extract slug and ecosystem from Reference URLs
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
		} else if match := wpThemeTracRegex.FindStringSubmatch(url); match != nil {
			tracSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Theme"
			}
		} else if match := wpThemeSvnRegex.FindStringSubmatch(url); match != nil {
			svnSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Theme"
			}
		} else if match := wordfencePluginRegex.FindStringSubmatch(url); match != nil {
			wordfenceSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Plugin"
			}
		} else if match := wordfenceThemeRegex.FindStringSubmatch(url); match != nil {
			wordfenceSlug = match[1]
			if urlEcosystem == "" {
				urlEcosystem = "WordPress:Theme"
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
			slug = s
			break
		}
	}

	if ecosystem == "WordPress" && urlEcosystem != "" {
		ecosystem = urlEcosystem
	}

	// 4. Description/Title Heuristics Fallback for ecosystem
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
	PostExtract(v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string)
}

// WordpressExtractor handles version extraction for WordPress CVEs.
type WordpressExtractor struct {
	Strategies []strategies.VersionStrategy
	Handler    WordpressHandler
}

var _ VersionExtractor = &WordpressExtractor{}

func (w *WordpressExtractor) getStrategies() []strategies.VersionStrategy {
	if len(w.Strategies) > 0 {
		return w.Strategies
	}

	return strategies.Default()
}

func (w *WordpressExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, _ git.RepoTagsCache, _ *http.Client) {
	if w.Handler != nil {
		w.Handler.PreExtract(&cve)
	}

	// 1. Extract slug and determine ecosystem using shared helper
	slug, ecosystem := extractWordPressSlugAndEcosystem(cve, v)

	if w.Handler != nil {
		w.Handler.PostExtract(v, metrics, slug, ecosystem)
	}

	if slug == "" {
		metrics.AddNotef("No WordPress slug found to attempt generating ECOSYSTEM ranges")
		if len(repos) == 0 {
			metrics.SetOutcome(models.NoRepos)
		}

		return
	}

	metrics.AddNotef("Attempting to generate ECOSYSTEM ranges for WordPress")

	gotVersions := false
	var allRanges []*osvschema.Range

	// 2. CNA Affected
	for _, cveAff := range cve.Containers.CNA.Affected {
		versionRanges := ExtractAffectedRanges(cveAff, w.getStrategies(), metrics)
		for _, r := range versionRanges {
			r.Range.Type = osvschema.Range_ECOSYSTEM
			allRanges = append(allRanges, r.Range)
		}
	}

	if len(allRanges) > 0 {
		gotVersions = true
		metrics.AddSource(models.VersionSourceAffected)
	}

	// 3. Fallback: CPE
	if !gotVersions {
		versionRanges, _ := strategies.CPEVersionExtraction(cve, metrics)
		for _, r := range versionRanges {
			r.Range.Type = osvschema.Range_ECOSYSTEM
			allRanges = append(allRanges, r.Range)
		}
		if len(allRanges) > 0 {
			gotVersions = true
		}
	}

	// 4. Fallback: Description
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
		metrics.Outcome = models.Successful // Override NoRepos set when no git repos were found
	}
}

// DefaultWordpressHandler provides empty implementations for the hooks.
type DefaultWordpressHandler struct{}

func (d *DefaultWordpressHandler) PreExtract(_ *models.CVE5) {}
func (d *DefaultWordpressHandler) PostExtract(_ *vulns.Vulnerability, _ *models.ConversionMetrics, _ string, _ string) {
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

func (p *PatchstackHandler) PostExtract(v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string) {
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
				metrics.AddNotef("Added wordpress.org reference link: %s", wpURL)
			}
		}
	}
}

// WPScanHandler implements WPScan specific quirks.
type WPScanHandler struct {
	DefaultWordpressHandler
}
