package cve5

import (
	"regexp"
	"strings"

	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
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
			if urlEcosystem == "" { urlEcosystem = "WordPress:Plugin" }
		} else if match := wpPluginSvnRegex.FindStringSubmatch(url); match != nil {
			svnSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Plugin" }
		} else if match := wordfencePluginRegex.FindStringSubmatch(url); match != nil {
			wordfenceSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Plugin" }
		} else if match := wpPluginOrgRegex.FindStringSubmatch(url); match != nil {
			wpOrgPluginSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Plugin" }
		} else if match := wpThemeOrgRegex.FindStringSubmatch(url); match != nil {
			wpOrgThemeSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Theme" }
		} else if match := patchstackPluginRegex.FindStringSubmatch(url); match != nil {
			patchstackPluginSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Plugin" }
		} else if match := patchstackThemeRegex.FindStringSubmatch(url); match != nil {
			patchstackThemeSlug = match[1]
			if urlEcosystem == "" { urlEcosystem = "WordPress:Theme" }
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
	if tracSlug != "" {
		urlSlug = tracSlug
	} else if svnSlug != "" {
		urlSlug = svnSlug
	} else if wordfenceSlug != "" {
		urlSlug = wordfenceSlug
	} else if wpOrgPluginSlug != "" {
		urlSlug = wpOrgPluginSlug
	} else if wpOrgThemeSlug != "" {
		urlSlug = wpOrgThemeSlug
	} else if patchstackPluginSlug != "" {
		urlSlug = patchstackPluginSlug
	} else if patchstackThemeSlug != "" {
		urlSlug = patchstackThemeSlug
	} else if patchstackVulnSlug != "" {
		urlSlug = patchstackVulnSlug
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
