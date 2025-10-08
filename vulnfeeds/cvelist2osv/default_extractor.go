package cvelist2osv

import (
	"fmt"
	"log/slog"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// DefaultVersionExtractor provides the default version extraction logic.
type DefaultVersionExtractor struct{}

// ExtractVersions for DefaultVersionExtractor.
func (d *DefaultVersionExtractor) ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, repos []string) {
	gotVersions := false
	affected := combineAffected(cve)
	repoTagsCache := git.RepoTagsCache{}
	for _, cveAff := range affected {
		versionRanges, _ := d.FindNormalAffectedRanges(cveAff, metrics)

		if len(versionRanges) == 0 {
			continue
		}

		gotVersions = true

		aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
		if err != nil {
			logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
		}

		v.Affected = append(v.Affected, aff)
		metrics.AddSource(VersionSourceAffected)
	}

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := cpeVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			gotVersions = true
			aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
			if err != nil {
				logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
			}

			v.Affected = append(v.Affected, aff)
		}
	}

	if !gotVersions {
		metrics.AddNote("No versions in CPEs so attempting extraction from description")
		versionRanges := textVersionExtraction(cve, metrics)
		aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
		if err != nil {
			logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
		}
		v.Affected = append(v.Affected, aff)
	}
}

func (d *DefaultVersionExtractor) FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) (versionRanges []osvschema.Range, versType VersionRangeType) {
	versionTypesCount := make(map[VersionRangeType]int)

	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}

		currentVersionType := toVersionRangeType(vers.VersionType)
		versionTypesCount[currentVersionType]++

		var introduced, fixed, lastaffected string

		// Quality check the version strings to avoid using filler content.
		vQuality := vulns.CheckQuality(vers.Version)
		if !vQuality.AtLeast(acceptableQuality) {
			metrics.AddNote("Version value for %s %s is filler or empty", affected.Vendor, affected.Product)
		}
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasRange := vLessThanQual.AtLeast(acceptableQuality) || vLTOEQual.AtLeast(acceptableQuality)
		metrics.AddNote("Range detected: %v", hasRange)
		// Handle cases where 'lessThan' is mistakenly the same as 'version'.
		if vers.LessThan != "" && vers.LessThan == vers.Version {
			metrics.AddNote("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version)
			hasRange = false
		}

		if hasRange {
			if vQuality.AtLeast(acceptableQuality) {
				introduced = vers.Version
				metrics.AddNote("%s - Introduced from version value - %s", vQuality.String(), vers.Version)
			}
			if vLessThanQual.AtLeast(acceptableQuality) {
				fixed = vers.LessThan
				metrics.AddNote("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan)
			} else if vLTOEQual.AtLeast(acceptableQuality) {
				lastaffected = vers.LessThanOrEqual
				metrics.AddNote("%s - LastAffected from LessThanOrEqual value- %s", vLTOEQual.String(), vers.LessThanOrEqual)
			}

			if introduced != "" && fixed != "" {
				versionRanges = append(versionRanges, cves.BuildVersionRange(introduced, "", fixed))
			} else if introduced != "" && lastaffected != "" {
				versionRanges = append(versionRanges, cves.BuildVersionRange(introduced, lastaffected, ""))
			}

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
		if vQuality.AtLeast(acceptableQuality) {
			versionRanges = append(versionRanges, cves.BuildVersionRange("0", vers.Version, ""))
			metrics.Notes = append(metrics.Notes, fmt.Sprintf("%s - Single version found %v - Assuming introduced = 0 and last affected = %v", vQuality, vers.Version, vers.Version))
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
