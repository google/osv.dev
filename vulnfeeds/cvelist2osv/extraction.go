package cvelist2osv

import (
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VersionExtractor defines the interface for different version extraction strategies.
type VersionExtractor interface {
	ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, repos []string)
	FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) ([]*osvschema.Range, VersionRangeType)
}

// GetVersionExtractor returns the appropriate VersionExtractor for a given CNA.
func GetVersionExtractor(cna string) VersionExtractor {
	switch cna {
	case "Linux":
		return &LinuxVersionExtractor{}
	default:
		return &DefaultVersionExtractor{}
	}
}
