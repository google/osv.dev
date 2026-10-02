package cve5

import (
	"net/http"
	"strings"

	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
)

// VersionExtractor defines the interface for different version extraction strategies.
type VersionExtractor interface {
	ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client)
}

// GetVersionExtractor returns the appropriate VersionExtractor configured with CNA-specific strategies.
func GetVersionExtractor(cna string) VersionExtractor {
	switch strings.ToLower(cna) {
	case "linux":
		return &LinuxVersionExtractor{
			Strategies: strategies.Linux(),
		}
	case "github_m", "github":
		return &DefaultVersionExtractor{
			Strategies: strategies.GitHub(),
		}
	case "mitre":
		return &DefaultVersionExtractor{
			Strategies: strategies.MITRE(),
		}
	default:
		return &DefaultVersionExtractor{
			Strategies: strategies.Default(),
		}
	}
}

// ExtractAffectedRanges runs the given strategy pipeline across an Affected block,
// tracking consumed version indices via ExtractionState and returning extracted ranges.
func ExtractAffectedRanges(affected models.Affected, strategyList []strategies.VersionStrategy, metrics *models.ConversionMetrics) []models.RangeWithMetadata {
	state := strategies.NewExtractionState(affected)

	for _, strategy := range strategyList {
		if state.AllConsumed() {
			break
		}

		prevCount := len(state.Ranges())
		strategy.Extract(state, metrics)
		if len(state.Ranges()) > prevCount {
			state.SetStrategyFrom(prevCount, strategy.Name())
			metrics.AddNotef("Strategy successful: %s", strategy.Name())
		}
	}

	return state.Ranges()
}
