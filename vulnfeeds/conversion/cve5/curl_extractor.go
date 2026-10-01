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
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

// CurlVersionExtractor provides the version extraction logic for curl CVE records.
type CurlVersionExtractor struct {
	Strategies []strategies.VersionStrategy
}

var _ VersionExtractor = &CurlVersionExtractor{}

func (cve *CurlVersionExtractor) getStrategies() []strategies.VersionStrategy {
	if len(cve.Strategies) > 0 {
		return cve.Strategies
	}

	return strategies.Curl()
}

func isGitVersion(v models.Versions) bool {
	if v.Status != "affected" {
		return false
	}

	return strategies.ToVersionRangeType(v.VersionType) == strategies.VersionRangeTypeGit ||
		c.IsGitCommitSHA(v.Version) ||
		c.IsGitCommitSHA(v.LessThan) ||
		c.IsGitCommitSHA(v.LessThanOrEqual)
}

func hasGitVersion(aff models.Affected) bool {
	return slices.ContainsFunc(aff.Versions, isGitVersion)
}

func hasGitRanges(affected []models.Affected) bool {
	return slices.ContainsFunc(affected, hasGitVersion)
}

func addUnresolvedRangesToVuln(v *vulns.Vulnerability, unRanges []models.RangeWithMetadata) {
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

// ExtractVersions for CurlVersionExtractor.
// If Git ranges are provided in the CVE record, we only add those Git ranges to the record
// and add the enumerated versions to the versions array rather than adding more ranges.
// Otherwise, it falls back to the default extraction pipeline.
func (cve *CurlVersionExtractor) ExtractVersions(cveRecord models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client) {
	affected := cveRecord.Containers.CNA.Affected
	if !hasGitRanges(affected) {
		defaultExtractor := &DefaultVersionExtractor{
			Strategies: cve.getStrategies(),
		}
		defaultExtractor.ExtractVersions(cveRecord, v, metrics, repos, cache, httpClient)

		return
	}

	// Extract only the Git ranges from the affected blocks that provide Git versions.
	var gitRanges []models.RangeWithMetadata
	for _, cveAff := range affected {
		if !hasGitVersion(cveAff) {
			continue
		}
		extracted := ExtractAffectedRanges(cveAff, cve.getStrategies(), metrics)
		for _, r := range extracted {
			if r.Range.GetType() == osvschema.Range_GIT || c.IsDirectGitRange(r) {
				gitRanges = append(gitRanges, r)
			}
		}
	}

	// Fallback if no Git ranges were extracted.
	if len(gitRanges) == 0 {
		defaultExtractor := &DefaultVersionExtractor{
			Strategies: cve.getStrategies(),
		}
		defaultExtractor.ExtractVersions(cveRecord, v, metrics, repos, cache, httpClient)

		return
	}

	// Extract enumerated versions from affected blocks (exact versions without ranges).
	var enumeratedVersions []string
	for _, cveAff := range affected {
		for _, vers := range cveAff.Versions {
			if vers.Status != "affected" || vers.Version == "" {
				continue
			}
			if isGitVersion(vers) {
				continue
			}
			hasRange := (vers.LessThan != "" && vers.LessThan != vers.Version) ||
				(vers.LessThanOrEqual != "" && vers.LessThanOrEqual != vers.Version) ||
				len(vers.Changes) > 0
			if hasRange {
				continue
			}
			if !vulns.CheckQuality(vers.Version).AtLeast(vulns.Spaces) {
				continue
			}
			enumeratedVersions = append(enumeratedVersions, vers.Version)
		}
	}
	slices.SortFunc(enumeratedVersions, strategies.CompareSemverLike)
	enumeratedVersions = slices.Compact(enumeratedVersions)

	// Attach the enumerated versions to the Git ranges so they populate v.Affected[...].Versions.
	for i := range gitRanges {
		gitRanges[i].Metadata.Versions = enumeratedVersions
	}

	successfulRepos := make(map[string]bool)
	resolvedRanges, unresolvedRanges, sR := c.ProcessRanges(gitRanges, repos, metrics, cache, httpClient)
	for _, s := range sR {
		successfulRepos[s] = true
	}

	if len(repos) == 0 && len(resolvedRanges) == 0 {
		metrics.SetOutcome(models.NoRepos)
		metrics.Outcome = models.NoRepos
		if len(unresolvedRanges) > 0 {
			addUnresolvedRangesToVuln(v, unresolvedRanges)
		} else if len(gitRanges) > 0 {
			metrics.UnresolvedRangesCount += len(gitRanges)
			addUnresolvedRangesToVuln(v, gitRanges)
		}

		return
	}

	if len(resolvedRanges) > 0 {
		metrics.SetOutcome(models.Successful)
		metrics.AddSource(models.VersionSourceAffected)
	}

	keys := slices.Collect(maps.Keys(successfulRepos))
	groupedRanges := c.GroupRanges(resolvedRanges)
	mergedAffected := c.MergeRangesAndCreateAffected(groupedRanges, nil, keys, metrics)
	for _, aff := range mergedAffected {
		slices.SortFunc(aff.GetVersions(), strategies.CompareSemverLike)
	}
	v.Affected = append(v.Affected, mergedAffected...)

	if len(unresolvedRanges) > 0 {
		addUnresolvedRangesToVuln(v, unresolvedRanges)
	}
}
