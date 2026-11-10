package cve5

import (
	"encoding/json"
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

const (
	tierTrac = iota
	tierSVN
	tierWordfence
	tierWPOrg
	tierPatchstackTyped
	tierPatchstackVuln
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

	nonSlugCharsRegex = regexp.MustCompile(`[^a-z0-9]+`)

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

type wpPackageTarget struct {
	slug        string
	ecosystem   string
	bestTier    int
	firstIdx    int
	matchedURLs []string
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

// extractWordPressPackages extracts all valid WordPress (slug, ecosystem) targets from the CVE
// and its reference URLs, ordered by source priority tier and first appearance.
func extractWordPressPackages(cve models.CVE5, v *vulns.Vulnerability) []wpPackageTarget {
	// 1. Core Check (Highest Priority)
	for _, aff := range cve.Containers.CNA.Affected {
		if strings.EqualFold(aff.Vendor, "wordpress") && strings.EqualFold(aff.Product, "wordpress") {
			return []wpPackageTarget{{
				slug:      "wordpress",
				ecosystem: wpEcosystemCore,
			}}
		}
	}

	// 2. Ecosystem fallback from CollectionURL
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

	// 3. Scan Reference URLs and group matches by lowercase slug.
	bySlug := make(map[string]*wpPackageTarget)
	var genericURLEco string

	recordMatch := func(slug, eco string, tier, idx int, url string) {
		key := strings.ToLower(slug)
		existing, ok := bySlug[key]
		if !ok {
			bySlug[key] = &wpPackageTarget{
				slug:        slug,
				ecosystem:   eco,
				bestTier:    tier,
				firstIdx:    idx,
				matchedURLs: []string{url},
			}

			return
		}
		existing.matchedURLs = append(existing.matchedURLs, url)
		if tier < existing.bestTier {
			existing.slug = slug
			existing.bestTier = tier
			if eco != "" {
				existing.ecosystem = eco
			}
		} else if existing.ecosystem == "" && eco != "" {
			existing.ecosystem = eco
		}
	}

	for idx, ref := range v.References {
		url := ref.GetUrl()

		if s := matchFirstRegex(url, wpPluginTracRegexes); s != "" {
			recordMatch(s, wpEcosystemPlugin, tierTrac, idx, url)
		} else if s := matchFirstRegex(url, wpThemeTracRegexes); s != "" {
			recordMatch(s, wpEcosystemTheme, tierTrac, idx, url)
		} else if s := matchSingleRegex(url, wpPluginSvnRegex); s != "" {
			recordMatch(s, wpEcosystemPlugin, tierSVN, idx, url)
		} else if s := matchSingleRegex(url, wpThemeSvnRegex); s != "" {
			recordMatch(s, wpEcosystemTheme, tierSVN, idx, url)
		} else if s := matchSingleRegex(url, wordfencePluginRegex); s != "" {
			recordMatch(s, wpEcosystemPlugin, tierWordfence, idx, url)
		} else if s := matchSingleRegex(url, wordfenceThemeRegex); s != "" {
			recordMatch(s, wpEcosystemTheme, tierWordfence, idx, url)
		} else if s := matchSingleRegex(url, wpPluginOrgRegex); s != "" {
			recordMatch(s, wpEcosystemPlugin, tierWPOrg, idx, url)
		} else if s := matchSingleRegex(url, wpThemeOrgRegex); s != "" {
			recordMatch(s, wpEcosystemTheme, tierWPOrg, idx, url)
		} else if s := matchSingleRegex(url, patchstackPluginRegex); s != "" {
			recordMatch(s, wpEcosystemPlugin, tierPatchstackTyped, idx, url)
		} else if s := matchSingleRegex(url, patchstackThemeRegex); s != "" {
			recordMatch(s, wpEcosystemTheme, tierPatchstackTyped, idx, url)
		} else if s := matchSingleRegex(url, patchstackVulnRegex); s != "" {
			recordMatch(s, "", tierPatchstackVuln, idx, url)
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

	if len(bySlug) == 0 {
		return nil
	}

	// 4. Fallback ecosystem from collectionURL, generic URL keywords, or description/title.
	fallbackEco := collectionEcosystem
	if fallbackEco == "" {
		fallbackEco = genericURLEco
	}
	if fallbackEco == "" {
		desc := strings.ToLower(models.EnglishDescription(cve.Containers.CNA.Descriptions))
		title := strings.ToLower(cve.Containers.CNA.Title)
		if strings.Contains(desc, "plugin") || strings.Contains(title, "plugin") {
			fallbackEco = wpEcosystemPlugin
		} else if strings.Contains(desc, "theme") || strings.Contains(title, "theme") {
			fallbackEco = wpEcosystemTheme
		} else {
			fallbackEco = wpEcosystemBase
		}
	}

	targets := make([]wpPackageTarget, 0, len(bySlug))
	for _, t := range bySlug {
		if t.ecosystem == "" {
			t.ecosystem = fallbackEco
		}
		targets = append(targets, *t)
	}

	slices.SortFunc(targets, func(a, b wpPackageTarget) int {
		if a.bestTier != b.bestTier {
			return a.bestTier - b.bestTier
		}

		return a.firstIdx - b.firstIdx
	})

	return targets
}

func slugifyWordPressProduct(product string) string {
	s := product
	for _, sep := range []string{" – ", " — ", " - ", " | ", " ("} {
		if before, _, ok := strings.Cut(s, sep); ok {
			s = before
		}
	}
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlugCharsRegex.ReplaceAllString(s, "-")

	return strings.Trim(s, "-")
}

func affectedVersionTokens(aff models.Affected) []string {
	var tokens []string
	for _, vers := range aff.Versions {
		for _, tok := range []string{vers.LessThanOrEqual, vers.LessThan, vers.Version} {
			if tok != "" && tok != "0" && tok != "*" {
				tokens = append(tokens, tok)
			}
		}
		for _, ch := range vers.Changes {
			if ch.At != "" {
				tokens = append(tokens, ch.At)
			}
		}
	}

	return tokens
}

// matchAffectedBlocksForTarget selects the models.Affected block(s) in a multi-product CVE
// that correspond to target, avoiding cross-contaminating versions across distinct plugins/themes
// or Free vs Pro editions.
func matchAffectedBlocksForTarget(affected []models.Affected, target wpPackageTarget) []models.Affected {
	lowerSlug := strings.ToLower(target.slug)
	var matched []models.Affected

	for _, aff := range affected {
		if strings.EqualFold(strings.TrimSpace(aff.PackageName), target.slug) {
			matched = append(matched, aff)
			continue
		}
		if slugifyWordPressProduct(aff.Product) == lowerSlug {
			matched = append(matched, aff)
		}
	}
	if len(matched) > 0 {
		return matched
	}

	// Fallback: check if a reference URL for this slug embeds a '/tags/<ver>/' matching a unique block.
	var tagMatched []models.Affected
	for _, aff := range affected {
		tokens := affectedVersionTokens(aff)
		matchedByTag := false
		for _, u := range target.matchedURLs {
			for _, tok := range tokens {
				if strings.Contains(u, "/tags/"+tok+"/") || strings.Contains(u, "/tags/v"+tok+"/") {
					matchedByTag = true
					break
				}
			}
			if matchedByTag {
				break
			}
		}
		if matchedByTag {
			tagMatched = append(tagMatched, aff)
		}
	}
	if len(tagMatched) == 1 {
		return tagMatched
	}

	return nil
}

// cloneCVEAffected deep-copies the Affected/Versions/Changes slices on cve so PreExtract
// and version sanitization never mutate the caller's backing arrays in place.
func cloneCVEAffected(cve *models.CVE5) {
	if len(cve.Containers.CNA.Affected) == 0 {
		return
	}
	clonedAff := slices.Clone(cve.Containers.CNA.Affected)
	for i := range clonedAff {
		if len(clonedAff[i].Versions) > 0 {
			clonedVers := slices.Clone(clonedAff[i].Versions)
			for j := range clonedVers {
				if len(clonedVers[j].Changes) > 0 {
					clonedVers[j].Changes = slices.Clone(clonedVers[j].Changes)
				}
			}
			clonedAff[i].Versions = clonedVers
		}
	}
	cve.Containers.CNA.Affected = clonedAff
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}

	return v
}

func containsDigit(s string) bool {
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}

	return false
}

func isLikelyVersionOrExpr(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	if strings.HasPrefix(s, "<") || strings.HasPrefix(s, ">") || strings.HasPrefix(s, "=") || strings.HasPrefix(s, "cpe:") {
		return true
	}

	return c.IsGitCommitSHA(s)
}

func sanitizeWordPressCVE(cve *models.CVE5) {
	for i := range cve.Containers.CNA.Affected {
		for j := range cve.Containers.CNA.Affected[i].Versions {
			vers := &cve.Containers.CNA.Affected[i].Versions[j]
			vers.Version = strings.TrimSpace(vers.Version)
			vers.LessThan = strings.TrimSpace(vers.LessThan)
			vers.LessThanOrEqual = strings.TrimSpace(vers.LessThanOrEqual)

			// Strip operator prefixes accidentally placed inside lessThanOrEqual / lessThan.
			if after, ok := strings.CutPrefix(vers.LessThanOrEqual, "<="); ok {
				vers.LessThanOrEqual = strings.TrimSpace(after)
			} else if after, ok := strings.CutPrefix(vers.LessThanOrEqual, "<"); ok {
				if vers.LessThan == "" {
					vers.LessThan = strings.TrimSpace(after)
				}
				vers.LessThanOrEqual = ""
			}

			if after, ok := strings.CutPrefix(vers.LessThan, "<="); ok {
				if vers.LessThanOrEqual == "" {
					vers.LessThanOrEqual = strings.TrimSpace(after)
				}
				vers.LessThan = ""
			} else if after, ok := strings.CutPrefix(vers.LessThan, "<"); ok {
				vers.LessThan = strings.TrimSpace(after)
			}

			// Handle single-bound "<= X" or "< X" placed inside version.
			if !strings.Contains(vers.Version, ",") {
				if after, ok := strings.CutPrefix(vers.Version, "<="); ok {
					if vers.LessThanOrEqual == "" && vers.LessThan == "" {
						vers.LessThanOrEqual = strings.TrimSpace(after)
					}
					vers.Version = "0"
				} else if after, ok := strings.CutPrefix(vers.Version, "<"); ok {
					if vers.LessThan == "" && vers.LessThanOrEqual == "" {
						vers.LessThan = strings.TrimSpace(after)
					}
					vers.Version = "0"
				}
			}

			// Strip leading 'v'/'V' before digits across fields.
			vers.Version = normalizeVersion(vers.Version)
			vers.LessThan = normalizeVersion(vers.LessThan)
			vers.LessThanOrEqual = normalizeVersion(vers.LessThanOrEqual)
			for k := range vers.Changes {
				vers.Changes[k].At = normalizeVersion(vers.Changes[k].At)
			}

			// Drop non-version filler text (e.g. "revision", "beta") in upper bounds, preserving "*".
			if vers.LessThan != "" && vers.LessThan != "*" && !containsDigit(vers.LessThan) {
				vers.LessThan = ""
			}
			if vers.LessThanOrEqual != "" && vers.LessThanOrEqual != "*" && !containsDigit(vers.LessThanOrEqual) {
				vers.LessThanOrEqual = ""
			}

			hasFiniteUpperBound := (vers.LessThan != "" && vers.LessThan != "*") ||
				(vers.LessThanOrEqual != "" && vers.LessThanOrEqual != "*") ||
				len(vers.Changes) > 0

			if hasFiniteUpperBound {
				if vers.Version == "*" || (vers.Version != "" && vers.Version != "0" && !isLikelyVersionOrExpr(vers.Version)) {
					vers.Version = "0"
				}
			}
		}
	}
}

// extractWPBlockRanges extracts ranges from a single models.Affected block, handling
// open-ended wildcard ("*") entries before running the configured strategy pipeline.
func (w *WordpressExtractor) extractWPBlockRanges(cveAff models.Affected, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	var openEndedRanges []models.RangeWithMetadata
	remainingVersions := make([]models.Versions, 0, len(cveAff.Versions))

	for _, vers := range cveAff.Versions {
		if vers.Status != "affected" {
			remainingVersions = append(remainingVersions, vers)
			continue
		}
		isWildcardAll := (vers.Version == "*" && vers.LessThan == "" && vers.LessThanOrEqual == "" && len(vers.Changes) == 0) ||
			vers.LessThanOrEqual == "*" ||
			vers.LessThan == "*"

		if isWildcardAll {
			intro := "0"
			if vers.Version != "" && vers.Version != "*" && isLikelyVersionOrExpr(vers.Version) {
				intro = vers.Version
			}
			vr := []*osvschema.Range{c.BuildVersionRange(intro, "", "")}
			openEndedRanges = append(openEndedRanges, c.ToRangeWithMetadata(vr, models.VersionSourceAffected)...)
			metrics.AddNotef("Wildcard affected version detected - emitting open-ended range from %s", intro)

			continue
		}
		remainingVersions = append(remainingVersions, vers)
	}

	var extracted []models.RangeWithMetadata
	extracted = append(extracted, openEndedRanges...)
	if len(remainingVersions) > 0 {
		filteredAff := cveAff
		filteredAff.Versions = remainingVersions
		extracted = append(extracted, ExtractAffectedRanges(filteredAff, w.getStrategies(), metrics)...)
	}
	if len(extracted) > 0 {
		metrics.AddSource(models.VersionSourceAffected)
	}

	return extracted
}

// sanitizeEcosystemRanges converts non-Git ranges into Range_ECOSYSTEM ranges and ensures
// that ranges sharing the same introduced version never mix fixed and last_affected events
// (which are mutually exclusive in the OSV schema when grouped by GroupAffectedRanges).
func sanitizeEcosystemRanges(rawRanges []models.RangeWithMetadata, metrics *models.ConversionMetrics) []*osvschema.Range {
	var candidates []*osvschema.Range
	hasFixedByIntro := make(map[string]bool)

	for _, r := range rawRanges {
		if r.Range == nil || r.Range.GetType() == osvschema.Range_GIT || c.IsDirectGitRange(r) {
			continue
		}
		ecoRange := proto.Clone(r.Range).(*osvschema.Range)
		ecoRange.Type = osvschema.Range_ECOSYSTEM
		ecoRange.Repo = ""
		candidates = append(candidates, ecoRange)

		var intro string
		hasFixed := false
		for _, e := range ecoRange.GetEvents() {
			if e.GetIntroduced() != "" {
				intro = e.GetIntroduced()
			}
			if e.GetFixed() != "" {
				hasFixed = true
			}
		}
		if hasFixed {
			hasFixedByIntro[intro] = true
		}

		if r.Metadata.Source != "" && !slices.Contains(metrics.VersionSources, r.Metadata.Source) {
			metrics.VersionSources = append(metrics.VersionSources, r.Metadata.Source)
		}
	}

	out := make([]*osvschema.Range, 0, len(candidates))
	for _, r := range candidates {
		var intro string
		hasFixed := false
		hasLastAffected := false
		for _, e := range r.GetEvents() {
			if e.GetIntroduced() != "" {
				intro = e.GetIntroduced()
			}
			if e.GetFixed() != "" {
				hasFixed = true
			}
			if e.GetLastAffected() != "" {
				hasLastAffected = true
			}
		}
		if hasFixedByIntro[intro] && hasLastAffected && !hasFixed {
			continue
		}
		if hasFixed && hasLastAffected {
			filtered := make([]*osvschema.Event, 0, len(r.GetEvents()))
			for _, e := range r.GetEvents() {
				if e.GetLastAffected() == "" {
					filtered = append(filtered, e)
				}
			}
			r.Events = filtered
		}
		out = append(out, r)
	}

	return out
}

func rangesEqualJSON(a, b []*osvschema.Range) bool {
	ba, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)

	return errA == nil && errB == nil && string(ba) == string(bb)
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

func (w *WordpressExtractor) extractAllCandidateRanges(cve models.CVE5, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	ranges := make([]models.RangeWithMetadata, 0, len(cve.Containers.CNA.Affected))
	for _, cveAff := range cve.Containers.CNA.Affected {
		ranges = append(ranges, w.extractWPBlockRanges(cveAff, metrics)...)
	}
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
	cloneCVEAffected(&cve)
	if w.Handler != nil {
		w.Handler.PreExtract(&cve)
	}
	sanitizeWordPressCVE(&cve)

	// 1. Extract WordPress package targets (slug + ecosystem) from references/metadata.
	targets := extractWordPressPackages(cve, v)

	// 2. Extract candidate version ranges once for single-affected CVEs (and Git resolution).
	var allRawRanges []models.RangeWithMetadata
	if len(cve.Containers.CNA.Affected) <= 1 {
		allRawRanges = w.extractAllCandidateRanges(cve, metrics)
	} else {
		for _, cveAff := range cve.Containers.CNA.Affected {
			allRawRanges = append(allRawRanges, w.extractWPBlockRanges(cveAff, metrics)...)
		}
	}

	// 3. Resolve GIT ranges when repositories or direct Git commit ranges are present.
	prevUnresolvedCount := metrics.UnresolvedRangesCount
	var unresolvedGitRanges []models.RangeWithMetadata
	hasDirectGit := slices.ContainsFunc(allRawRanges, c.IsDirectGitRange)

	if len(repos) > 0 || hasDirectGit {
		successfulRepos := make(map[string]bool)
		var resolvedGitRanges []models.RangeWithMetadata

		if len(allRawRanges) > 0 {
			r, un, sR := c.ProcessRanges(cloneRangesWithMetadata(allRawRanges), repos, metrics, cache, httpClient)
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

	// 4. Generate WordPress ECOSYSTEM ranges when valid slug target(s) are available.
	if len(targets) == 0 {
		metrics.AddNotef("No WordPress slug found to attempt generating ECOSYSTEM ranges")
		if len(v.Affected) == 0 {
			if len(unresolvedGitRanges) > 0 {
				addUnresolvedRangesToVuln(v, unresolvedGitRanges)
			} else if len(repos) == 0 {
				metrics.SetOutcome(models.NoRepos)
				metrics.Outcome = models.NoRepos
				if len(allRawRanges) > 0 {
					metrics.UnresolvedRangesCount += len(allRawRanges)
					addUnresolvedRangesToVuln(v, allRawRanges)
				}
			}
		}

		return
	}

	metrics.AddNotef("Attempting to generate ECOSYSTEM ranges for WordPress")

	emittedEcosystem := false
	if len(cve.Containers.CNA.Affected) <= 1 {
		primary := targets[0]
		if w.Handler != nil {
			w.Handler.PostExtract(v, metrics, primary.slug, primary.ecosystem)
		}
		ecoRanges := sanitizeEcosystemRanges(allRawRanges, metrics)
		if len(ecoRanges) > 0 {
			c.AddAffected(v, &osvschema.Affected{
				Package: &osvschema.Package{
					Ecosystem: primary.ecosystem,
					Name:      primary.slug,
				},
				Ranges: ecoRanges,
			}, metrics)
			emittedEcosystem = true
		}
	} else {
		// Multi-product CVE: match each slug target to its corresponding CNA Affected block(s).
		for _, target := range targets {
			matchedBlocks := matchAffectedBlocksForTarget(cve.Containers.CNA.Affected, target)
			if len(matchedBlocks) == 0 {
				continue
			}
			var targetRaw []models.RangeWithMetadata
			for _, blk := range matchedBlocks {
				targetRaw = append(targetRaw, w.extractWPBlockRanges(blk, metrics)...)
			}
			ecoRanges := sanitizeEcosystemRanges(targetRaw, metrics)
			if len(ecoRanges) == 0 {
				continue
			}
			if w.Handler != nil {
				w.Handler.PostExtract(v, metrics, target.slug, target.ecosystem)
			}
			v.Affected = append(v.Affected, &osvschema.Affected{
				Package: &osvschema.Package{
					Ecosystem: target.ecosystem,
					Name:      target.slug,
				},
				Ranges: ecoRanges,
			})
			metrics.ResolvedRangesCount += len(ecoRanges)
			emittedEcosystem = true
		}

		// Fallback when only 1 slug target exists and all CNA Affected blocks share identical ranges.
		if !emittedEcosystem && len(targets) == 1 {
			primary := targets[0]
			var firstBlockRanges []*osvschema.Range
			allSame := true
			for i, blk := range cve.Containers.CNA.Affected {
				blkEco := sanitizeEcosystemRanges(w.extractWPBlockRanges(blk, metrics), metrics)
				if len(blkEco) == 0 {
					allSame = false
					break
				}
				if i == 0 {
					firstBlockRanges = blkEco
				} else if !rangesEqualJSON(firstBlockRanges, blkEco) {
					allSame = false
					break
				}
			}
			if allSame && len(firstBlockRanges) > 0 {
				if w.Handler != nil {
					w.Handler.PostExtract(v, metrics, primary.slug, primary.ecosystem)
				}
				c.AddAffected(v, &osvschema.Affected{
					Package: &osvschema.Package{
						Ecosystem: primary.ecosystem,
						Name:      primary.slug,
					},
					Ranges: firstBlockRanges,
				}, metrics)
				emittedEcosystem = true
			}
		}
	}

	if emittedEcosystem {
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

// PatchstackHandler implements Patchstack specific quirks.
type PatchstackHandler struct {
	DefaultWordpressHandler
}

func hasExistingWPOrgRef(refs []*osvschema.Reference, slug string, ecosystem string) bool {
	rx := wpPluginOrgRegex
	if ecosystem == wpEcosystemTheme {
		rx = wpThemeOrgRegex
	}
	for _, ref := range refs {
		if matchedSlug := matchSingleRegex(ref.GetUrl(), rx); strings.EqualFold(matchedSlug, slug) {
			return true
		}
	}

	return false
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

	if baseURL == "" || hasExistingWPOrgRef(v.References, slug, ecosystem) {
		return
	}

	wpURL := baseURL + slug + "/"
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
