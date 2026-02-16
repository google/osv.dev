package cvelist2osv

import (
	"cmp"
	"errors"
	"strconv"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VersionRangeType represents the type of versioning scheme for a range.
type VersionRangeType int

const acceptableQuality = vulns.Spaces

const (
	VersionRangeTypeUnknown VersionRangeType = iota
	VersionRangeTypeGit
	VersionRangeTypeSemver
	VersionRangeTypeEcosystem
)

// String returns the string representation of a VersionRangeType.
func (vrt VersionRangeType) String() string {
	switch vrt {
	case VersionRangeTypeGit:
		return "git"
	case VersionRangeTypeEcosystem:
		return "ecosystem"
	case VersionRangeTypeSemver:
		return "semver"
	default:
		return "unknown"
	}
}

// toVersionRangeType converts a string to a VersionRangeType.
func toVersionRangeType(s string) VersionRangeType {
	switch strings.ToLower(s) {
	case "git":
		return VersionRangeTypeGit
	case "semver":
		return VersionRangeTypeSemver
	default:
		// Other version types like "semver" are treated as ecosystem ranges.
		return VersionRangeTypeEcosystem
	}
}

// findCPEVersionRanges extracts version ranges and CPE strings from the CNA's
// CPE applicability statements in a CVE record.
func findCPEVersionRanges(cve models.CVE5) (versionRanges []*osvschema.Range, cpes []string, err error) {
	// TODO(jesslowe): Add logic to also extract CPEs from the 'affected' field (e.g., CVE-2025-1110).
	for _, c := range cve.Containers.CNA.CPEApplicability {
		for _, node := range c.Nodes {
			if node.Operator != "OR" {
				continue
			}
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				cpes = append(cpes, match.Criteria)

				// If no start version is given, assume the vulnerability starts from version "0".
				if match.VersionStartIncluding == "" {
					match.VersionStartIncluding = "0"
				}

				if match.VersionEndExcluding != "" {
					versionRanges = append(versionRanges, cves.BuildVersionRange(match.VersionStartIncluding, "", match.VersionEndExcluding))
				} else if match.VersionEndIncluding != "" {
					versionRanges = append(versionRanges, cves.BuildVersionRange(match.VersionStartIncluding, match.VersionEndIncluding, ""))
				}
			}
		}
	}
	if len(versionRanges) == 0 {
		return nil, nil, errors.New("no versions extracted from CPEs")
	}

	return versionRanges, cpes, nil
}

// compareSemverLike provides a custom comparison function for version strings that may not
// strictly adhere to the SemVer specification. It compares versions numerically,
// part by part (major, minor, patch).
func compareSemverLike(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	minLen := min(len(partsA), len(partsB))
	for i := range minLen {
		// Convert parts to integers for numerical comparison.
		// We ignore the error, so non-numeric parts default to 0.
		numA, _ := strconv.Atoi(partsA[i])
		numB, _ := strconv.Atoi(partsB[i])
		if c := cmp.Compare(numA, numB); c != 0 {
			return c
		}
	}
	// If lengths are the same, they're equal.
	if len(partsA) == len(partsB) {
		return 0
	}

	// Determine which version has extra parts and what the result
	// should be if those parts are non-zero.
	var longerParts []string
	var result int
	// Assume 'b' is greater
	if len(partsA) > len(partsB) {
		longerParts = partsA
		result = 1 // 'a' is actually greater
	} else if len(partsA) < len(partsB) {
		longerParts = partsB
		result = -1
	}

	// Check if any of the extra parts are non-zero.
	for i := minLen; i < len(longerParts); i++ {
		num, _ := strconv.Atoi(longerParts[i])
		if num != 0 {
			return result
		}
	}

	// All extra parts were zero, so the versions are effectively equal.
	return 0
}
