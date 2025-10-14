package cvelist2osv

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// LinuxVersionExtractor provides the version extraction logic for Linux kernel CVEs.
type LinuxVersionExtractor struct {
	DefaultVersionExtractor
}

var _ VersionExtractor = &LinuxVersionExtractor{}

// handleAffected takes an array of cves.Affected and handles how to extract them
func (l *LinuxVersionExtractor) handleAffected(v *vulns.Vulnerability, affected []cves.Affected, metrics *ConversionMetrics) bool {
	hasGit := false
	gotVersions := false
	for _, cveAff := range affected {
		var versionRanges []osvschema.Range
		var versionType VersionRangeType
		if cveAff.DefaultStatus == "affected" {
			versionRanges, versionType = findInverseAffectedRanges(cveAff, metrics)
		} else {
			versionRanges, versionType = l.FindNormalAffectedRanges(cveAff, metrics)
		}
		if (versionType == VersionRangeTypeGit && hasGit) || len(versionRanges) == 0 {
			continue
		}

		gotVersions = true

		if versionType == VersionRangeTypeGit {
			hasGit = true
		}
		aff := createLinuxAffected(versionRanges, versionType, cveAff.Repo)
		v.Affected = append(v.Affected, aff)
		metrics.AddSource(VersionSourceAffected)
	}

	return gotVersions
}

// ExtractVersions for LinuxVersionExtractor.
func (l *LinuxVersionExtractor) ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, _ []string) {
	gotVersions := l.handleAffected(v, cve.Containers.CNA.Affected, metrics)

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := cpeVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			aff := createLinuxAffected(versionRanges, VersionRangeTypeEcosystem, "")
			v.Affected = append(v.Affected, aff)
		}
	}
}

func createLinuxAffected(versionRanges []osvschema.Range, versionType VersionRangeType, repo string) osvschema.Affected {
	var aff osvschema.Affected
	for _, vr := range versionRanges {
		if versionType == VersionRangeTypeGit {
			vr.Type = osvschema.RangeGit
			vr.Repo = repo
		} else {
			vr.Type = osvschema.RangeEcosystem
		}
		aff.Ranges = append(aff.Ranges, vr)
	}
	if versionType != VersionRangeTypeGit {
		aff.Package = osvschema.Package{
			Ecosystem: string(osvschema.EcosystemLinux),
			Name:      "Kernel",
		}
	}

	return aff
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. This is common in Linux kernel CVEs where a product is
// considered affected by default, and only unaffected versions are listed.
// It sorts the introduced and fixed versions to create chronological ranges.
func findInverseAffectedRanges(cveAff cves.Affected, metrics *ConversionMetrics) (ranges []osvschema.Range, versType VersionRangeType) {
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
			ranges = append(ranges, cves.BuildVersionRange(introduced[index], "", f))
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

func (l *LinuxVersionExtractor) FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) ([]osvschema.Range, VersionRangeType) {
	versionTypesCount := make(map[VersionRangeType]int)
	var versionRanges []osvschema.Range
	for _, vers := range affected.Versions {
		ranges, currentVersionType, shouldContinue := initialNormalExtraction(vers, metrics, versionTypesCount)
		versionRanges = append(versionRanges, ranges...)
		if shouldContinue {
			continue
		}
		// In this case only vers.Version exists which either means that it is _only_ that version that is
		// affected, but more likely, it affects up to that version. It could also mean that the range is given
		// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.
		metrics.AddNote("Only version exists")

		if currentVersionType == VersionRangeTypeGit {
			versionRanges = append(versionRanges, cves.BuildVersionRange(vers.Version, "", ""))
			continue
		}

		// As a fallback, assume a single version means it's the last affected version.
		if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
			versionRanges = append(versionRanges, cves.BuildVersionRange("0", vers.Version, ""))
			metrics.Notes = append(metrics.Notes, fmt.Sprintf("Single version found %v - Assuming introduced = 0 and last affected = %v", vers.Version, vers.Version))
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
