package cve5

import (
	"net/http"
	"slices"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// LinuxVersionExtractor provides the version extraction logic for Linux kernel CVEs.
type LinuxVersionExtractor struct {
	Strategies []strategies.VersionStrategy
}

var _ VersionExtractor = &LinuxVersionExtractor{}

// handleAffected takes an array of models.Affected and handles how to extract them.
// A single CNA Affected block in Linux CVEs can contain both git commit ranges and
// semver release ranges, so extracted ranges are partitioned individually by range type.
func (l *LinuxVersionExtractor) handleAffected(v *vulns.Vulnerability, affected []models.Affected, metrics *models.ConversionMetrics) bool {
	if len(l.Strategies) == 0 {
		l.Strategies = strategies.Linux()
	}

	hasGit := false
	gotVersions := false
	var directEcoRanges []*osvschema.Range
	var inverseEcoRanges []*osvschema.Range
	var inverseUnaffectedBefore string

	for _, cveAff := range affected {
		if cveAff.DefaultStatus == "affected" {
			if b := extractZeroUnaffectedUpperBound(cveAff); b != "" {
				if inverseUnaffectedBefore == "" || strategies.CompareSemverLike(b, inverseUnaffectedBefore) < 0 {
					inverseUnaffectedBefore = b
				}
			}
		}

		versionRangesWithMetadata := ExtractAffectedRanges(cveAff, l.Strategies, metrics)
		if len(versionRangesWithMetadata) == 0 {
			continue
		}

		var gitRanges []*osvschema.Range
		var ecoRanges []*osvschema.Range
		for _, r := range versionRangesWithMetadata {
			if r.Range.GetType() == osvschema.Range_GIT && c.IsDirectGitRange(r) {
				gitRanges = append(gitRanges, r.Range)
			} else {
				ecoRanges = append(ecoRanges, r.Range)
			}
		}

		if len(gitRanges) > 0 && !hasGit {
			hasGit = true
			gotVersions = true
			aff := createLinuxAffected(gitRanges, true, cveAff.Repo)
			metrics.AddSource(models.VersionSourceAffected)
			c.AddAffected(v, aff, metrics)
		}

		if len(ecoRanges) > 0 {
			gotVersions = true
			if cveAff.DefaultStatus == "affected" {
				inverseEcoRanges = append(inverseEcoRanges, ecoRanges...)
			} else {
				directEcoRanges = append(directEcoRanges, ecoRanges...)
			}
		}
	}

	mergedEcoRanges := mergeLinuxEcosystemRanges(directEcoRanges, inverseEcoRanges, inverseUnaffectedBefore)
	if len(mergedEcoRanges) > 0 {
		aff := createLinuxAffected(mergedEcoRanges, false, "")
		metrics.AddSource(models.VersionSourceAffected)
		c.AddAffected(v, aff, metrics)
	}

	return gotVersions
}

// extractZeroUnaffectedUpperBound inspects a defaultStatus=="affected" block for an entry
// of the form {version: "0", lessThan: X, status: "unaffected"} and returns normalized X.
func extractZeroUnaffectedUpperBound(cveAff models.Affected) string {
	for _, vers := range cveAff.Versions {
		if vers.Status == "unaffected" && vers.Version == "0" && vers.LessThan != "" && vers.LessThan != "*" {
			if strings.Count(vers.LessThan, ".") == 1 {
				return vers.LessThan + ".0"
			}

			return vers.LessThan
		}
	}

	return ""
}

func rangeIntroFixed(r *osvschema.Range) (intro, fixed string, ok bool) {
	evts := r.GetEvents()
	if len(evts) != 2 {
		return "", "", false
	}
	intro = evts[0].GetIntroduced()
	fixed = evts[1].GetFixed()
	if intro == "" || fixed == "" {
		return "", "", false
	}

	return intro, fixed, true
}

func compareLinuxIntro(a, b string) int {
	if a == "0" && b == "0" {
		return 0
	}
	if a == "0" {
		return -1
	}
	if b == "0" {
		return 1
	}

	return strategies.CompareSemverLike(a, b)
}

// mergeLinuxEcosystemRanges reconciles direct semver ranges (from defaultStatus=="unaffected"
// blocks) with inverse semver ranges (from defaultStatus=="affected" blocks):
//   - When explicit non-"0" backport intervals are present in directRanges and the inverse block
//     declares [0, X) unaffected, an inverse interval spanning across X ([intro < X < fixed)) is
//     clamped to [X, fixed) so earlier EOL backport intervals (e.g. [6.0.10, 6.1)) stay disjoint.
//   - When both blocks emit an [introduced, fixed) range with the same fixed endpoint (e.g.
//     direct [0, 5.15.225) vs inverse [5.11.0, 5.15.225) in CVE-2026-100080, or direct backport
//     [5.4.225, 5.4.268) vs inverse [0, 5.4.268) in CVE-2023-52457), the tighter (larger)
//     introduced bound is kept instead of duplicating or widening the branch range.
func mergeLinuxEcosystemRanges(directRanges, inverseRanges []*osvschema.Range, unaffectedBefore string) []*osvschema.Range {
	if len(directRanges) == 0 {
		return inverseRanges
	}
	if len(inverseRanges) == 0 {
		return directRanges
	}

	hasNonZeroDirect := false
	for _, r := range directRanges {
		if intro, _, ok := rangeIntroFixed(r); ok && intro != "0" {
			hasNonZeroDirect = true
			break
		}
	}

	adjustedInverse := make([]*osvschema.Range, 0, len(inverseRanges))
	for _, r := range inverseRanges {
		intro, fixed, ok := rangeIntroFixed(r)
		if ok && hasNonZeroDirect && unaffectedBefore != "" &&
			compareLinuxIntro(intro, unaffectedBefore) < 0 &&
			strategies.CompareSemverLike(unaffectedBefore, fixed) < 0 {
			adjustedInverse = append(adjustedInverse, c.BuildVersionRange(unaffectedBefore, "", fixed))
			continue
		}
		adjustedInverse = append(adjustedInverse, r)
	}

	var combined []*osvschema.Range
	combined = append(combined, adjustedInverse...)

	for _, dr := range directRanges {
		dIntro, dFixed, ok := rangeIntroFixed(dr)
		if !ok {
			combined = append(combined, dr)
			continue
		}

		matchedFixedIdx := -1
		for i, cr := range combined {
			_, cFixed, cOk := rangeIntroFixed(cr)
			if cOk && strategies.CompareSemverLike(dFixed, cFixed) == 0 {
				matchedFixedIdx = i
				break
			}
		}

		if matchedFixedIdx >= 0 {
			cIntro, cFixed, _ := rangeIntroFixed(combined[matchedFixedIdx])
			if compareLinuxIntro(dIntro, cIntro) > 0 {
				combined[matchedFixedIdx] = c.BuildVersionRange(dIntro, "", cFixed)
			}

			continue
		}

		combined = append(combined, dr)
	}

	slices.SortStableFunc(combined, func(a, b *osvschema.Range) int {
		aIntro, aFixed, aOk := rangeIntroFixed(a)
		bIntro, bFixed, bOk := rangeIntroFixed(b)
		if !aOk || !bOk {
			return 0
		}
		if cmp := compareLinuxIntro(aIntro, bIntro); cmp != 0 {
			return cmp
		}

		return strategies.CompareSemverLike(aFixed, bFixed)
	})

	return combined
}

// ExtractVersions for LinuxVersionExtractor.
func (l *LinuxVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, _ []string, _ git.RepoTagsCache, _ *http.Client) {
	gotVersions := l.handleAffected(v, cve.Containers.CNA.Affected, metrics)

	if !gotVersions {
		metrics.AddNotef("No versions in affected, attempting to extract from CPE")
		versionRanges, err := strategies.CPEVersionExtraction(cve, metrics)
		if err != nil {
			logger.Warn("Error when extracting CPE versions")
		}
		if len(versionRanges) != 0 {
			ranges := make([]*osvschema.Range, 0, len(versionRanges))
			for _, r := range versionRanges {
				ranges = append(ranges, r.Range)
			}
			aff := createLinuxAffected(ranges, false, "")
			c.AddAffected(v, aff, metrics)
		}
	}
}

func createLinuxAffected(versionRanges []*osvschema.Range, isGit bool, repo string) *osvschema.Affected {
	var aff osvschema.Affected
	for _, vr := range versionRanges {
		if isGit {
			vr.Type = osvschema.Range_GIT
			if vr.GetRepo() == "" {
				vr.Repo = repo
			}
		} else {
			vr.Type = osvschema.Range_ECOSYSTEM
			vr.Repo = ""
		}
		aff.Ranges = append(aff.Ranges, vr)
	}
	if !isGit {
		aff.Package = &osvschema.Package{
			Ecosystem: string(osvconstants.EcosystemLinux),
			Name:      "Kernel",
		}
	}

	return &aff
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions.
func findInverseAffectedRanges(cveAff models.Affected, metrics *models.ConversionMetrics) (ranges []*osvschema.Range, versType strategies.VersionRangeType) {
	return strategies.FindInverseAffectedRanges(cveAff, metrics)
}
