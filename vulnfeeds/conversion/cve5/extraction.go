package cve5

import (
	"net/http"
	"strings"

	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
)

// VersionExtractor defines the interface for different version extraction strategies.
type VersionExtractor interface {
	ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client)
	FindNormalAffectedRanges(affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType)
}

// GetVersionExtractor returns the appropriate VersionExtractor configured with CNA-specific strategies.
func GetVersionExtractor(cna string) VersionExtractor {
	switch strings.ToLower(cna) {
	case "linux":
		return &LinuxVersionExtractor{
			DefaultVersionExtractor: DefaultVersionExtractor{
				Strategies: LinuxStrategies(),
			},
		}
	case "github_m", "github":
		return &DefaultVersionExtractor{
			Strategies: GitHubStrategies(),
		}
	case "mitre":
		return &DefaultVersionExtractor{
			Strategies: MITREStrategies(),
		}
	default:
		return &DefaultVersionExtractor{
			Strategies: DefaultStrategies(),
		}
	}
}
