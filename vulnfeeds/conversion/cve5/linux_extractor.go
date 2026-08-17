package cve5

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// LinuxVersionExtractor provides the version extraction logic for Linux kernel CVEs.
type LinuxVersionExtractor struct {
	DefaultVersionExtractor
}

var _ VersionExtractor = &LinuxVersionExtractor{}

// handleAffected takes an array of models.Affected and handles how to extract them
func (l *LinuxVersionExtractor) handleAffected(v *vulns.Vulnerability, affected []models.Affected, metrics *models.ConversionMetrics) bool {
	if len(l.Strategies) == 0 {
		l.Strategies = LinuxStrategies()
	}

	hasGit := false
	gotVersions := false
	for _, cveAff := range affected {
		var versionRanges []*osvschema.Range
		var versionType VersionRangeType
		if cveAff.DefaultStatus == "affected" {
			versionRanges, versionType = findInverseAffectedRanges(cveAff, metrics)
		} else {
			var versionRangesWithMetadata []models.RangeWithMetadata
			versionRangesWithMetadata, versionType = l.FindNormalAffectedRanges(cveAff, metrics)
			for _, r := range versionRangesWithMetadata {
				versionRanges = append(versionRanges, r.Range)
			}
		}
		if (versionType == VersionRangeTypeGit && hasGit) || len(versionRanges) == 0 {
			continue
		}

		gotVersions = true

		if versionType == VersionRangeTypeGit {
			hasGit = true
		}
		aff := createLinuxAffected(versionRanges, versionType, cveAff.Repo)
		metrics.AddSource(models.VersionSourceAffected)
		c.AddAffected(v, aff, metrics)
	}

	return gotVersions
}

// ExtractVersions for LinuxVersionExtractor.
func (l *LinuxVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, _ []string, _ git.RepoTagsCache, _ *http.Client) {
	gotVersions := l.handleAffected(v, cve.Containers.CNA.Affected, metrics)

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, err := cpeVersionExtraction(cve, metrics)
		if err != nil {
			logger.Warn("Error when extracting CPE versions")
		}
		if len(versionRanges) != 0 {
			var ranges []*osvschema.Range
			for _, r := range versionRanges {
				ranges = append(ranges, r.Range)
			}
			aff := createLinuxAffected(ranges, VersionRangeTypeEcosystem, "")
			v.Affected = append(v.Affected, aff)
		}
	}
}

func createLinuxAffected(versionRanges []*osvschema.Range, versionType VersionRangeType, repo string) *osvschema.Affected {
	var aff osvschema.Affected
	for _, vr := range versionRanges {
		if versionType == VersionRangeTypeGit {
			vr.Type = osvschema.Range_GIT
			vr.Repo = repo
		} else {
			vr.Type = osvschema.Range_ECOSYSTEM
		}
		aff.Ranges = append(aff.Ranges, vr)
	}
	if versionType != VersionRangeTypeGit {
		aff.Package = &osvschema.Package{
			Ecosystem: string(osvconstants.EcosystemLinux),
			Name:      "Kernel",
		}
	}

	return &aff
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. This is common in Linux kernel CVEs where a product is
// considered affected by default, and only unaffected versions are listed.
// It sorts the introduced and fixed versions to create chronological ranges.
func findInverseAffectedRanges(cveAff models.Affected, metrics *models.ConversionMetrics) (ranges []*osvschema.Range, versType VersionRangeType) {
	var introduced []string
	fixed := make([]string, 0, len(cveAff.Versions))
	for _, vers := range cveAff.Versions {
		versionValue := vers.Version
		if vers.Status == "affected" {
			numParts := len(strings.Split(versionValue, "."))
			switch numParts {
			case 2:
				introduced = append(introduced, versionValue+".0")
			case 3:
				introduced = append(introduced, versionValue)
			default:
				metrics.AddNote("Bad non-semver version given: %s", versionValue)
				continue
			}
		}
		if vers.Status != "unaffected" {
			continue
		}

		if versionValue == "0" || toVersionRangeType(vers.VersionType) != VersionRangeTypeSemver {
			continue
		}
		fixed = append(fixed, versionValue)
		// Infer the next introduced version from the 'lessThanOrEqual' field.
		// For example, if "5.10.*" is unaffected, the next introduced version is "5.11.0".
		minorVers := strings.Split(vers.LessThanOrEqual, ".*")[0]
		parts := strings.Split(minorVers, ".")
		if len(parts) > 1 {
			if intMin, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				nextIntroduced := fmt.Sprintf("%s.%d.0", parts[0], intMin+1)
				introduced = append(introduced, nextIntroduced)
			}
		}
	}
	slices.SortFunc(introduced, compareSemverLike)
	slices.SortFunc(fixed, compareSemverLike)

	// If the first fixed version is earlier than the first introduced, assume introduction from "0".
	if len(fixed) > 0 && len(introduced) > 0 && compareSemverLike(fixed[0], introduced[0]) < 0 {
		introduced = append([]string{"0"}, introduced...)
	}

	// Create ranges by pairing sorted introduced and fixed versions.
	for index, f := range fixed {
		if index < len(introduced) {
			ranges = append(ranges, c.BuildVersionRange(introduced[index], "", f))
			metrics.AddNote("Introduced from version value - %s", introduced[index])
			metrics.AddNote("Fixed from version value - %s", f)
		}
	}

	if len(ranges) != 0 {
		return ranges, VersionRangeTypeSemver
	}
	metrics.AddNote("no ranges found")

	return nil, VersionRangeTypeUnknown
}
