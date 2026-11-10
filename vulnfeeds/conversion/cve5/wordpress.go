package cve5

import (
	"maps"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

const (
	wpEcosystemBase   = string(osvconstants.EcosystemWordPress)
	wpEcosystemCore   = wpEcosystemBase + ":Core"
	wpEcosystemPlugin = wpEcosystemBase + ":Plugin"
	wpEcosystemTheme  = wpEcosystemBase + ":Theme"
)

var (
	wpPluginTracRegexes = []*regexp.Regexp{
		regexp.MustCompile(`plugins\.trac\.wordpress\.org/browser/([^/?#]+)`),
		regexp.MustCompile(`plugins\.trac\.wordpress\.org/log/([^/?#]+)`),
		regexp.MustCompile(`plugins\.trac\.wordpress\.org/changeset/\d+/([^/?#]+)`),
		regexp.MustCompile(`plugins\.trac\.wordpress\.org/changeset\?[^#]*(?:%40|@)([^/?#&%]+)`),
	}
	wpThemeTracRegexes = []*regexp.Regexp{
		regexp.MustCompile(`themes\.trac\.wordpress\.org/browser/([^/?#]+)`),
		regexp.MustCompile(`themes\.trac\.wordpress\.org/log/([^/?#]+)`),
		regexp.MustCompile(`themes\.trac\.wordpress\.org/changeset/\d+/([^/?#]+)`),
		regexp.MustCompile(`themes\.trac\.wordpress\.org/changeset\?[^#]*(?:%40|@)([^/?#&%]+)`),
	}

	wpPluginSvnRegex = regexp.MustCompile(`plugins\.svn\.wordpress\.org/([^/?#]+)`)
	wpThemeSvnRegex  = regexp.MustCompile(`themes\.svn\.wordpress\.org/([^/?#]+)`)
	wpPluginOrgRegex = regexp.MustCompile(`wordpress\.org/plugins/([^/?#]+)`)
	wpThemeOrgRegex  = regexp.MustCompile(`wordpress\.org/themes/([^/?#]+)`)

	wordfencePluginRegex = regexp.MustCompile(`(?i)wordfence\.com/threat-intel/vulnerabilities/wordpress-plugins/([^/?#]+)`)
	wordfenceThemeRegex  = regexp.MustCompile(`(?i)wordfence\.com/threat-intel/vulnerabilities/wordpress-themes/([^/?#]+)`)

	patchstackVulnRegex   = regexp.MustCompile(`(?i)patchstack\.com/database/vulnerability/([^/?#]+)`)
	patchstackPluginRegex = regexp.MustCompile(`(?i)patchstack\.com/database/wordpress/plugin/([^/?#]+)`)
	patchstackThemeRegex  = regexp.MustCompile(`(?i)patchstack\.com/database/wordpress/theme/([^/?#]+)`)

	reservedWPSlugs = []string{
		"trunk",
		"tags",
		"branches",
		"search",
		"browse",
		"about",
		"developers",
	}
)

type slugCandidate struct {
	slug      string
	ecosystem string
}

func isValidWordPressSlug(s string) bool {
	if s == "" || slices.Contains(reservedWPSlugs, strings.ToLower(s)) {
		return false
	}
	for i := range len(s) {
		ch := s[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isAlphaNum && ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}

	return true
}

func matchFirstRegex(url string, regexes []*regexp.Regexp) string {
	for _, rx := range regexes {
		if match := rx.FindStringSubmatch(url); match != nil && isValidWordPressSlug(match[1]) {
			return match[1]
		}
	}

	return ""
}

func matchSingleRegex(url string, rx *regexp.Regexp) string {
	if match := rx.FindStringSubmatch(url); match != nil && isValidWordPressSlug(match[1]) {
		return match[1]
	}

	return ""
}

// extractWordPressSlugAndEcosystem unifies the logic to extract the slug and determine
// the specific WordPress ecosystem (Core, Plugin, Theme) for a given CVE.
func extractWordPressSlugAndEcosystem(cve models.CVE5, v *vulns.Vulnerability) (string, string) {
	// 1. Core Check (Highest Priority)
	for _, aff := range cve.Containers.CNA.Affected {
		if strings.EqualFold(aff.Vendor, "wordpress") && strings.EqualFold(aff.Product, "wordpress") {
			return "wordpress", wpEcosystemCore
		}
	}

	// 2. Ecosystem Extraction from CollectionURL
	var collectionEcosystem string
	for _, aff := range cve.Containers.CNA.Affected {
		switch strings.TrimSuffix(aff.CollectionURL, "/") {
		case "https://wordpress.org/themes":
			collectionEcosystem = wpEcosystemTheme
		case "https://wordpress.org/plugins":
			collectionEcosystem = wpEcosystemPlugin
		}
		if collectionEcosystem != "" {
			break
		}
	}

	// 3. Extract slug and ecosystem from Reference URLs, keeping slug and ecosystem paired per priority tier.
	var (
		tracCand           slugCandidate
		svnCand            slugCandidate
		wordfenceCand      slugCandidate
		wpOrgCand          slugCandidate
		patchstackTypeCand slugCandidate
		patchstackVulnCand slugCandidate
		genericURLEco      string
	)

	for _, ref := range v.References {
		url := ref.GetUrl()

		if s := matchFirstRegex(url, wpPluginTracRegexes); s != "" && tracCand.slug == "" {
			tracCand = slugCandidate{slug: s, ecosystem: wpEcosystemPlugin}
		} else if s := matchFirstRegex(url, wpThemeTracRegexes); s != "" && tracCand.slug == "" {
			tracCand = slugCandidate{slug: s, ecosystem: wpEcosystemTheme}
		} else if s := matchSingleRegex(url, wpPluginSvnRegex); s != "" && svnCand.slug == "" {
			svnCand = slugCandidate{slug: s, ecosystem: wpEcosystemPlugin}
		} else if s := matchSingleRegex(url, wpThemeSvnRegex); s != "" && svnCand.slug == "" {
			svnCand = slugCandidate{slug: s, ecosystem: wpEcosystemTheme}
		} else if s := matchSingleRegex(url, wordfencePluginRegex); s != "" && wordfenceCand.slug == "" {
			wordfenceCand = slugCandidate{slug: s, ecosystem: wpEcosystemPlugin}
		} else if s := matchSingleRegex(url, wordfenceThemeRegex); s != "" && wordfenceCand.slug == "" {
			wordfenceCand = slugCandidate{slug: s, ecosystem: wpEcosystemTheme}
		} else if s := matchSingleRegex(url, wpPluginOrgRegex); s != "" && wpOrgCand.slug == "" {
			wpOrgCand = slugCandidate{slug: s, ecosystem: wpEcosystemPlugin}
		} else if s := matchSingleRegex(url, wpThemeOrgRegex); s != "" && wpOrgCand.slug == "" {
			wpOrgCand = slugCandidate{slug: s, ecosystem: wpEcosystemTheme}
		} else if s := matchSingleRegex(url, patchstackPluginRegex); s != "" && patchstackTypeCand.slug == "" {
			patchstackTypeCand = slugCandidate{slug: s, ecosystem: wpEcosystemPlugin}
		} else if s := matchSingleRegex(url, patchstackThemeRegex); s != "" && patchstackTypeCand.slug == "" {
			patchstackTypeCand = slugCandidate{slug: s, ecosystem: wpEcosystemTheme}
		} else if s := matchSingleRegex(url, patchstackVulnRegex); s != "" && patchstackVulnCand.slug == "" {
			patchstackVulnCand = slugCandidate{slug: s}
		}

		if genericURLEco == "" {
			lowerURL := strings.ToLower(url)
			if strings.Contains(lowerURL, "/theme/") || strings.Contains(lowerURL, "/themes/") {
				genericURLEco = wpEcosystemTheme
			} else if strings.Contains(lowerURL, "/plugin/") || strings.Contains(lowerURL, "/plugins/") {
				genericURLEco = wpEcosystemPlugin
			}
		}
	}

	candidates := []slugCandidate{
		tracCand,
		svnCand,
		wordfenceCand,
		wpOrgCand,
		patchstackTypeCand,
		patchstackVulnCand,
	}

	var chosen slugCandidate
	for _, cand := range candidates {
		if cand.slug != "" {
			chosen = cand
			break
		}
	}

	ecosystem := chosen.ecosystem
	if ecosystem == "" {
		ecosystem = collectionEcosystem
	}
	if ecosystem == "" {
		ecosystem = genericURLEco
	}

	// 4. Description/Title Heuristics Fallback for ecosystem
	if ecosystem == "" {
		desc := strings.ToLower(models.EnglishDescription(cve.Containers.CNA.Descriptions))
		title := strings.ToLower(cve.Containers.CNA.Title)

		if strings.Contains(desc, "plugin") || strings.Contains(title, "plugin") {
			ecosystem = wpEcosystemPlugin
		} else if strings.Contains(desc, "theme") || strings.Contains(title, "theme") {
			ecosystem = wpEcosystemTheme
		} else {
			ecosystem = wpEcosystemBase
		}
	}

	return chosen.slug, ecosystem
}

// WordpressHandler defines hooks for CNA-specific logic.
type WordpressHandler interface {
	PreExtract(cve *models.CVE5)
	PostExtract(v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string)
}

// WordpressExtractor handles version extraction for WordPress CVEs.
type WordpressExtractor struct {
	DefaultVersionExtractor

	Handler WordpressHandler
}

var _ VersionExtractor = &WordpressExtractor{}

func (w *WordpressExtractor) extractCandidateRanges(cve models.CVE5, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	ranges := w.handleAffected(cve.Containers.CNA.Affected, metrics)
	if len(ranges) > 0 {
		return ranges
	}

	metrics.AddNotef("No versions in affected, attempting to extract from CPE")
	cpeRanges, _ := strategies.CPEVersionExtraction(cve, metrics)
	if len(cpeRanges) > 0 {
		return cpeRanges
	}

	metrics.AddNotef("No versions in CPEs so attempting extraction from description")
	textRanges := c.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Containers.CNA.Descriptions), metrics, models.VersionSourceDescription)
	if len(textRanges) > 0 {
		metrics.AddNotef("Extracted versions from description: %v", textRanges)
	}

	return textRanges
}

func cloneRangesWithMetadata(ranges []models.RangeWithMetadata) []models.RangeWithMetadata {
	cloned := make([]models.RangeWithMetadata, 0, len(ranges))
	for _, r := range ranges {
		var rng *osvschema.Range
		if r.Range != nil {
			rng = proto.Clone(r.Range).(*osvschema.Range)
		}
		cloned = append(cloned, models.RangeWithMetadata{
			Range:    rng,
			Metadata: r.Metadata,
		})
	}

	return cloned
}

func (w *WordpressExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client) {
	if w.Handler != nil {
		w.Handler.PreExtract(&cve)
	}

	// 1. Extract slug and determine ecosystem using shared helper.
	slug, ecosystem := extractWordPressSlugAndEcosystem(cve, v)

	if w.Handler != nil {
		w.Handler.PostExtract(v, metrics, slug, ecosystem)
	}

	// 2. Extract candidate version ranges once across affected -> CPE -> description.
	rawRanges := w.extractCandidateRanges(cve, metrics)

	// 3. Resolve GIT ranges when repositories or direct Git commit ranges are present.
	prevUnresolvedCount := metrics.UnresolvedRangesCount
	var unresolvedGitRanges []models.RangeWithMetadata
	hasDirectGit := slices.ContainsFunc(rawRanges, c.IsDirectGitRange)

	if len(repos) > 0 || hasDirectGit {
		successfulRepos := make(map[string]bool)
		var resolvedGitRanges []models.RangeWithMetadata

		if len(rawRanges) > 0 {
			r, un, sR := c.ProcessRanges(cloneRangesWithMetadata(rawRanges), repos, metrics, cache, httpClient)
			resolvedGitRanges = append(resolvedGitRanges, r...)
			unresolvedGitRanges = append(unresolvedGitRanges, un...)
			for _, repo := range sR {
				successfulRepos[repo] = true
			}
			if len(r) == 0 {
				metrics.AddNotef("Failed to convert git versions to commits")
			}
		}

		var commits []models.AffectedCommit
		if len(repos) > 0 && httpClient != nil {
			references := c.DeduplicateRefs(identifyPossibleURLs(cve))
			extractedCommits, err := c.ExtractCommitsFromRefs(references, httpClient, cache)
			if err != nil {
				metrics.AddNotef("Failed to extract commits from references: %v", err)
			}
			if len(extractedCommits) > 0 {
				commits = extractedCommits
				for _, commit := range commits {
					successfulRepos[commit.Repo] = true
				}
				if len(resolvedGitRanges) == 0 {
					metrics.AddSource(models.VersionSourceRefs)
				}
			}
		}

		if len(resolvedGitRanges) > 0 || len(commits) > 0 {
			keys := slices.Collect(maps.Keys(successfulRepos))
			groupedRanges := c.GroupRanges(resolvedGitRanges)
			gitAffected := c.MergeRangesAndCreateAffected(groupedRanges, commits, keys, metrics)
			for _, aff := range gitAffected {
				aff.Package = nil // Keep GIT ranges separate without WordPress package metadata.
			}
			v.Affected = append(v.Affected, gitAffected...)
			metrics.SetOutcome(models.Successful)
		}
	}

	// 4. Generate WordPress ECOSYSTEM ranges when a valid slug is available.
	if slug == "" {
		metrics.AddNotef("No WordPress slug found to attempt generating ECOSYSTEM ranges")
		if len(v.Affected) == 0 {
			if len(unresolvedGitRanges) > 0 {
				addUnresolvedRangesToVuln(v, unresolvedGitRanges)
			} else if len(repos) == 0 {
				metrics.SetOutcome(models.NoRepos)
				metrics.Outcome = models.NoRepos
				if len(rawRanges) > 0 {
					metrics.UnresolvedRangesCount += len(rawRanges)
					addUnresolvedRangesToVuln(v, rawRanges)
				}
			}
		}

		return
	}

	metrics.AddNotef("Attempting to generate ECOSYSTEM ranges for WordPress")

	var ecoRanges []*osvschema.Range
	for _, r := range rawRanges {
		if r.Range == nil || r.Range.GetType() == osvschema.Range_GIT || c.IsDirectGitRange(r) {
			continue
		}
		ecoRange := proto.Clone(r.Range).(*osvschema.Range)
		ecoRange.Type = osvschema.Range_ECOSYSTEM
		ecoRange.Repo = ""
		ecoRanges = append(ecoRanges, ecoRange)

		if r.Metadata.Source != "" && !slices.Contains(metrics.VersionSources, r.Metadata.Source) {
			metrics.VersionSources = append(metrics.VersionSources, r.Metadata.Source)
		}
	}

	if len(ecoRanges) > 0 {
		aff := &osvschema.Affected{
			Package: &osvschema.Package{
				Ecosystem: ecosystem,
				Name:      slug,
			},
			Ranges: ecoRanges,
		}
		c.AddAffected(v, aff, metrics)
		// Ranges resolved as WordPress ECOSYSTEM ranges should not be counted as unresolved.
		if len(unresolvedGitRanges) > 0 {
			metrics.UnresolvedRangesCount = prevUnresolvedCount
		}
		metrics.Outcome = models.Successful
	} else if len(v.Affected) == 0 {
		metrics.UnresolvedRangesCount = prevUnresolvedCount
		metrics.Outcome = models.NoRanges
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
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}

	return v
}

func (w *WordfenceHandler) PreExtract(cve *models.CVE5) {
	for i := range cve.Containers.CNA.Affected {
		for j := range cve.Containers.CNA.Affected[i].Versions {
			vers := &cve.Containers.CNA.Affected[i].Versions[j]
			vers.Version = normalizeVersion(vers.Version)
			vers.LessThan = normalizeVersion(vers.LessThan)
			vers.LessThanOrEqual = normalizeVersion(vers.LessThanOrEqual)
			for k := range vers.Changes {
				vers.Changes[k].At = normalizeVersion(vers.Changes[k].At)
			}
		}
	}
}

// PatchstackHandler implements Patchstack specific quirks.
type PatchstackHandler struct {
	DefaultWordpressHandler
}

func (p *PatchstackHandler) PostExtract(v *vulns.Vulnerability, metrics *models.ConversionMetrics, slug string, ecosystem string) {
	if slug == "" {
		return
	}

	var baseURL string
	switch ecosystem {
	case wpEcosystemPlugin:
		baseURL = "https://wordpress.org/plugins/"
	case wpEcosystemTheme:
		baseURL = "https://wordpress.org/themes/"
	}

	if baseURL == "" {
		return
	}

	wpURL := baseURL + slug + "/"
	exists := slices.ContainsFunc(v.References, func(ref *osvschema.Reference) bool {
		return ref.GetUrl() == wpURL
	})
	if !exists {
		v.References = append(v.References, &osvschema.Reference{
			Type: osvschema.Reference_WEB,
			Url:  wpURL,
		})
		sort.Slice(v.References, func(i, j int) bool {
			if v.References[i].GetUrl() != v.References[j].GetUrl() {
				return v.References[i].GetUrl() < v.References[j].GetUrl()
			}

			return v.References[i].GetType() < v.References[j].GetType()
		})
		metrics.AddNotef("Added wordpress.org reference link: %s", wpURL)
	}
}

// WPScanHandler implements WPScan specific quirks.
type WPScanHandler struct {
	DefaultWordpressHandler
}

// PreExtract normalizes legacy V4-converted WPScan records where "< X" was encoded
// with both version and lessThan set to X (e.g. version: "2.52", lessThan: "2.52").
func (w *WPScanHandler) PreExtract(cve *models.CVE5) {
	for i := range cve.Containers.CNA.Affected {
		for j := range cve.Containers.CNA.Affected[i].Versions {
			vers := &cve.Containers.CNA.Affected[i].Versions[j]
			if vers.LessThan != "" && vers.Version == vers.LessThan {
				vers.Version = "0"
			}
		}
	}
}
