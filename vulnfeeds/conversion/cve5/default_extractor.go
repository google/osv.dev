package cve5

import (
	"cmp"
	"maps"
	"net/http"
	"slices"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultVersionExtractor provides version extraction logic using a configurable pipeline of strategies.
type DefaultVersionExtractor struct {
	Strategies []VersionStrategy
}

func (d *DefaultVersionExtractor) getStrategies() []VersionStrategy {
	var strategies []VersionStrategy
	if len(d.Strategies) > 0 {
		strategies = slices.Clone(d.Strategies)
	} else {
		strategies = DefaultStrategies()
	}

	slices.SortStableFunc(strategies, func(a, b VersionStrategy) int {
		return cmp.Compare(a.Priority(), b.Priority())
	})

	return strategies
}

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
func (d *DefaultVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client) {
	gotVersions := false

	ranges := d.handleAffected(cve.Containers.CNA.Affected, metrics)
	successfulRepos := make(map[string]bool)
	var resolvedRanges []models.RangeWithMetadata
	var unresolvedRanges []models.RangeWithMetadata

	processRanges := func(nr []models.RangeWithMetadata) bool {
		r, un, sR := c.ProcessRanges(nr, repos, metrics, cache, httpClient)
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

	addUnresolvedRanges := func(unRanges []models.RangeWithMetadata) {
		if len(unRanges) == 0 {
			return
		}
		if v.DatabaseSpecific == nil {
			v.DatabaseSpecific = &structpb.Struct{Fields: make(map[string]*structpb.Value)}
		} else if v.DatabaseSpecific.Fields == nil {
			v.DatabaseSpecific.Fields = make(map[string]*structpb.Value)
		}
		unresolvedRangesList := c.CreateUnresolvedRanges(unRanges)
		if err := c.AddFieldToDatabaseSpecific(v.DatabaseSpecific, "unresolved_ranges", unresolvedRangesList); err != nil {
			logger.Warn("failed to make database specific: %v", err)
		}
	}

	// Exit early if no repositories are available to resolve remaining versions.
	if len(repos) == 0 && !gotVersions {
		metrics.SetOutcome(models.NoRepos)
		metrics.Outcome = models.NoRepos
		if len(unresolvedRanges) > 0 {
			addUnresolvedRanges(unresolvedRanges)
		} else if len(ranges) > 0 {
			metrics.UnresolvedRangesCount += len(ranges)
			addUnresolvedRanges(ranges)
		}

		return
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

	addUnresolvedRanges(unresolvedRanges)
}

func (d *DefaultVersionExtractor) FindNormalAffectedRanges(affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType) {
	versionTypesCount := make(map[VersionRangeType]int)
	var versionRanges []models.RangeWithMetadata
	strategies := d.getStrategies()

	for _, vers := range affected.Versions {
		for _, strategy := range strategies {
			ranges, currentVersionType, handled := strategy.Extract(vers, affected, metrics)
			if handled {
				if len(ranges) > 0 {
					metrics.AddNote("Strategy successful: %s", strategy.Name())
					versionTypesCount[currentVersionType]++
					versionRanges = append(versionRanges, ranges...)
				}

				break
			}
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
