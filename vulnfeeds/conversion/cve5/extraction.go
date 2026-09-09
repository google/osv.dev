package cve5

import (
	"net/http"

	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
)

// VersionExtractor defines the interface for different version extraction strategies.
type VersionExtractor interface {
	ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client)
	FindNormalAffectedRanges(affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType)
}

// GetVersionExtractor returns the appropriate VersionExtractor for a given CNA.
func GetVersionExtractor(cna string) VersionExtractor {
	switch cna {
	case "Linux":
		return &LinuxVersionExtractor{}
	case "Wordfence":
		return &WordpressExtractor{Handler: &WordfenceHandler{}}
	case "Patchstack":
		return &WordpressExtractor{Handler: &PatchstackHandler{}}
	case "WPScan":
		return &WordpressExtractor{Handler: &WPScanHandler{}}
	default:
		return &DefaultVersionExtractor{}
	}
}
