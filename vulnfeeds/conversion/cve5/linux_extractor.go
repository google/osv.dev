package cve5

import (
	"net/http"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// LinuxVersionExtractor provides the version extraction logic for Linux kernel CVEs.
type LinuxVersionExtractor struct {
	Strategies []strategies.VersionStrategy
}

var _ VersionExtractor = &LinuxVersionExtractor{}

// handleAffected takes an array of models.Affected and handles how to extract them
func (l *LinuxVersionExtractor) handleAffected(v *vulns.Vulnerability, affected []models.Affected, metrics *models.ConversionMetrics) bool {
	if len(l.Strategies) == 0 {
		l.Strategies = strategies.Linux()
	}

	hasGit := false
	gotVersions := false
	for _, cveAff := range affected {
		versionRangesWithMetadata := ExtractAffectedRanges(cveAff, l.Strategies, metrics)
		if len(versionRangesWithMetadata) == 0 {
			continue
		}

		isGit := versionRangesWithMetadata[0].Range.GetType() == osvschema.Range_GIT
		versionRanges := make([]*osvschema.Range, 0, len(versionRangesWithMetadata))
		for _, r := range versionRangesWithMetadata {
			versionRanges = append(versionRanges, r.Range)
		}
		if isGit && hasGit {
			continue
		}

		gotVersions = true

		if isGit {
			hasGit = true
		}
		aff := createLinuxAffected(versionRanges, isGit, cveAff.Repo)
		metrics.AddSource(models.VersionSourceAffected)
		c.AddAffected(v, aff, metrics)
	}

	return gotVersions
}

// ExtractVersions for LinuxVersionExtractor.
func (l *LinuxVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, _ []string, _ git.RepoTagsCache, _ *http.Client) {
	gotVersions := l.handleAffected(v, cve.Containers.CNA.Affected, metrics)

	if !gotVersions {
		metrics.AddNotef("No versions in affected, attempting to extract from CPE")
		versionRanges, err := strategies.CPEVersionExtraction(cve, metrics)
		if err != nil {
			logger.Warn("Error when extracting CPE versions")
		}
		if len(versionRanges) != 0 {
			ranges := make([]*osvschema.Range, 0, len(versionRanges))
			for _, r := range versionRanges {
				ranges = append(ranges, r.Range)
			}
			aff := createLinuxAffected(ranges, false, "")
			c.AddAffected(v, aff, metrics)
		}
	}
}

func createLinuxAffected(versionRanges []*osvschema.Range, isGit bool, repo string) *osvschema.Affected {
	var aff osvschema.Affected
	for _, vr := range versionRanges {
		if isGit {
			vr.Type = osvschema.Range_GIT
			vr.Repo = repo
		} else {
			vr.Type = osvschema.Range_ECOSYSTEM
		}
		aff.Ranges = append(aff.Ranges, vr)
	}
	if !isGit {
		aff.Package = &osvschema.Package{
			Ecosystem: string(osvconstants.EcosystemLinux),
			Name:      "Kernel",
		}
	}

	return &aff
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions.
func findInverseAffectedRanges(cveAff models.Affected, metrics *models.ConversionMetrics) (ranges []*osvschema.Range, versType strategies.VersionRangeType) {
	return strategies.FindInverseAffectedRanges(cveAff, metrics)
}
