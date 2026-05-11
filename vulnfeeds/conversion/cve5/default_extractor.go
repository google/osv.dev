package cve5

import (
	"maps"
	"slices"

	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// DefaultVersionExtractor provides the default version extraction logic.
type DefaultVersionExtractor struct{}

func (d *DefaultVersionExtractor) handleAffected(affected []models.Affected, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	var ranges []models.RangeWithMetadata
	for _, cveAff := range affected {
		versionRanges, _ := d.FindNormalAffectedRanges(cveAff, metrics)

		if len(versionRanges) == 0 {
			continue
		}
		ranges = append(ranges, versionRanges...)
		metrics.AddSource(models.VersionSourceAffected)
	}

	return ranges
}

// ExtractVersions for DefaultVersionExtractor.
func (d *DefaultVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string) {
	gotVersions := false

	repoTagsCache := git.NewRepoTagsCache()

	ranges := d.handleAffected(cve.Containers.CNA.Affected, metrics)
	successfulRepos := make(map[string]bool)
	var resolvedRanges []models.RangeWithMetadata
	var unresolvedRanges []models.RangeWithMetadata

	processRanges := func(nr []models.RangeWithMetadata) bool {
		r, un, sR := c.ProcessRanges(nr, repos, metrics, repoTagsCache, models.VersionSourceAffected)
		resolvedRanges = append(resolvedRanges, r...)
		unresolvedRanges = append(unresolvedRanges, un...)
		for _, s := range sR {
			successfulRepos[s] = true
		}
		if len(r) == 0 {
			metrics.AddNote("Failed to convert git versions to commits")
			return false
		}

		return true
	}

	if len(ranges) != 0 {
		if processRanges(ranges) {
			gotVersions = true
			metrics.SetOutcome(models.Successful)
		}
	}

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := cpeVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			if processRanges(versionRanges) {
				gotVersions = true
			}
		}
	}

	if !gotVersions {
		metrics.AddNote("No versions in CPEs so attempting extraction from description")
		textRanges := c.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Containers.CNA.Descriptions), metrics, models.VersionSourceDescription)
		if len(textRanges) > 0 {
			metrics.AddNote("Extracted versions from description: %v", textRanges)
		}
		if len(textRanges) != 0 {
			processRanges(textRanges)
		}
	}

	keys := slices.Collect(maps.Keys(successfulRepos))
	groupedRanges := c.GroupRanges(resolvedRanges)
	affected := c.MergeRangesAndCreateAffected(groupedRanges, nil, keys, metrics)
	v.Affected = append(v.Affected, affected...)

	if len(unresolvedRanges) > 0 {
		unresolvedRangesList := c.CreateUnresolvedRanges(unresolvedRanges)
		if err := c.AddFieldToDatabaseSpecific(v.DatabaseSpecific, "unresolved_ranges", unresolvedRangesList); err != nil {
			logger.Warn("failed to make database specific: %v", err)
		}
	}
}

func (d *DefaultVersionExtractor) FindNormalAffectedRanges(affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType) {
	versionTypesCount := make(map[VersionRangeType]int)
	var versionRanges []models.RangeWithMetadata
	for _, vers := range affected.Versions {
		ranges, _, shouldContinue := initialNormalExtraction(vers, metrics, versionTypesCount)
		if len(ranges) > 0 {
			versionRanges = append(versionRanges, c.ToRangeWithMetadata(ranges, models.VersionSourceAffected)...)
		}

		if shouldContinue {
			continue
		}
		// In this case only vers.Version exists which either means that it is _only_ that version that is
		// affected, but more likely, it affects up to that version. It could also mean that the range is given
		// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.
		metrics.AddNote("Only version exists")

		av, err := git.ParseVersionRange(vers.Version)
		if err == nil {
			if av.Introduced == "" {
				continue
			}

			if av.Fixed != "" {
				vr := []*osvschema.Range{c.BuildVersionRange(av.Introduced, "", av.Fixed)}
				versionRanges = append(versionRanges, c.ToRangeWithMetadata(vr, models.VersionSourceAffected)...)

				continue
			} else if av.LastAffected != "" {
				vr := []*osvschema.Range{c.BuildVersionRange(av.Introduced, av.LastAffected, "")}
				versionRanges = append(versionRanges, c.ToRangeWithMetadata(vr, models.VersionSourceAffected)...)

				continue
			}
		}

		// Try to extract versions from text like "before 1.4.7".
		possibleVersions := c.ExtractVersionsFromText(nil, vers.Version, metrics, models.VersionSourceAffected)

		if possibleVersions != nil {
			metrics.AddNote("Versions retrieved from text but not used CURRENTLY")
			continue
		}

		// As a fallback, assume a single version means it's the last affected version.
		if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
			vr := []*osvschema.Range{c.BuildVersionRange("0", vers.Version, "")}
			versionRanges = append(versionRanges, c.ToRangeWithMetadata(vr, models.VersionSourceAffected)...)
			metrics.AddNote("Single version found %v - Assuming introduced = 0 and last affected = %v", vers.Version, vers.Version)
		}
	}

	// Determine the most frequent version type to return as the range type.
	maxCount := 0
	mostFrequentVersionType := VersionRangeTypeEcosystem
	for versionType, count := range versionTypesCount {
		if count > maxCount {
			maxCount = count
			mostFrequentVersionType = versionType
		}
	}

	return versionRanges, mostFrequentVersionType
}
