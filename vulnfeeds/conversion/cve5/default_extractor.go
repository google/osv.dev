package cve5

import (
	"maps"
	"net/http"
	"slices"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultVersionExtractor provides version extraction logic using a configurable pipeline of strategies.
type DefaultVersionExtractor struct {
	Strategies []strategies.VersionStrategy
}

func (d *DefaultVersionExtractor) getStrategies() []strategies.VersionStrategy {
	if len(d.Strategies) > 0 {
		return d.Strategies
	}

	return strategies.Default()
}

func (d *DefaultVersionExtractor) handleAffected(affected []models.Affected, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	var ranges []models.RangeWithMetadata
	for _, cveAff := range affected {
		versionRanges := ExtractAffectedRanges(cveAff, d.getStrategies(), metrics)

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
			metrics.AddNotef("Failed to convert git versions to commits")
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
		metrics.AddNotef("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := strategies.CPEVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			if processRanges(versionRanges) {
				gotVersions = true
			}
		}
	}

	if !gotVersions {
		metrics.AddNotef("No versions in CPEs so attempting extraction from description")
		textRanges := c.ExtractVersionsFromText(nil, models.EnglishDescription(cve.Containers.CNA.Descriptions), metrics, models.VersionSourceDescription)
		if len(textRanges) > 0 {
			metrics.AddNotef("Extracted versions from description: %v", textRanges)
		}
		if len(textRanges) != 0 {
			processRanges(textRanges)
		}
	}

	references := identifyPossibleURLs(cve)
	commits, err := c.ExtractCommitsFromRefs(references, httpClient, cache)
	if err != nil {
		metrics.AddNotef("Failed to extract commits from references: %v", err)
	}

	keys := slices.Collect(maps.Keys(successfulRepos))
	groupedRanges := c.GroupRanges(resolvedRanges)
	affected := c.MergeRangesAndCreateAffected(groupedRanges, commits, keys, metrics)
	v.Affected = append(v.Affected, affected...)

	addUnresolvedRanges(unresolvedRanges)
}
