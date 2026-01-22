package cvelist2osv

import (
	"fmt"
	"log/slog"

	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// DefaultVersionExtractor provides the default version extraction logic.
type DefaultVersionExtractor struct{}

func (d *DefaultVersionExtractor) handleAffected(affected []models.Affected, metrics *models.ConversionMetrics) []*osvschema.Range {
	var ranges []*osvschema.Range
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

	repoTagsCache := git.RepoTagsCache{}

	ranges := d.handleAffected(cve.Containers.CNA.Affected, metrics)

	if len(ranges) != 0 {
		aff, err := gitVersionsToCommits(cve.Metadata.CVEID, ranges, repos, metrics, repoTagsCache)
		if err != nil {
			logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
		} else {
			gotVersions = true
		}
		conversion.AddAffected(v, aff, metrics)
	}

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := cpeVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
			if err != nil {
				logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
			} else {
				gotVersions = true
			}

			conversion.AddAffected(v, aff, metrics)
		}
	}

	if !gotVersions {
		metrics.AddNote("No versions in CPEs so attempting extraction from description")
		versionRanges := textVersionExtraction(cve, metrics)
		if len(versionRanges) != 0 {
			aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
			if err != nil {
				logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
			}
			conversion.AddAffected(v, aff, metrics)
		}
	}
}

func (d *DefaultVersionExtractor) FindNormalAffectedRanges(affected models.Affected, metrics *models.ConversionMetrics) ([]*osvschema.Range, VersionRangeType) {
	versionTypesCount := make(map[VersionRangeType]int)
	var versionRanges []*osvschema.Range
	for _, vers := range affected.Versions {
		ranges, _, shouldContinue := initialNormalExtraction(vers, metrics, versionTypesCount)
		if len(ranges) > 0 {
			versionRanges = append(versionRanges, ranges...)
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
				versionRanges = append(versionRanges, cves.BuildVersionRange(av.Introduced, "", av.Fixed))
				continue
			} else if av.LastAffected != "" {
				versionRanges = append(versionRanges, cves.BuildVersionRange(av.Introduced, av.LastAffected, ""))
				continue
			}
		}

		// Try to extract versions from text like "before 1.4.7".
		possibleVersions, notes := cves.ExtractVersionsFromText(nil, vers.Version)

		for _, note := range notes {
			metrics.AddNote("%s", note)
		}

		if possibleVersions != nil {
			metrics.AddNote("Versions retrieved from text but not used CURRENTLY")
			continue
		}

		// As a fallback, assume a single version means it's the last affected version.
		if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
			versionRanges = append(versionRanges, cves.BuildVersionRange("0", vers.Version, ""))
			metrics.Notes = append(metrics.Notes, fmt.Sprintf("Single version found %v - Assuming introduced = 0 and last affected = %v", vers.Version, vers.Version))
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
