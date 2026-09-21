package cve5

import (
	"cmp"
	"strconv"
	"strings"

	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
)

// VersionRangeType represents the type of versioning scheme for a range.
type VersionRangeType = strategies.VersionRangeType

const (
	VersionRangeTypeUnknown   = strategies.VersionRangeTypeUnknown
	VersionRangeTypeGit       = strategies.VersionRangeTypeGit
	VersionRangeTypeSemver    = strategies.VersionRangeTypeSemver
	VersionRangeTypeEcosystem = strategies.VersionRangeTypeEcosystem
)

// toVersionRangeType converts a string to a VersionRangeType.
func toVersionRangeType(s string) VersionRangeType {
	return strategies.ToVersionRangeType(s)
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
		if v := cmp.Compare(numA, numB); v != 0 {
			return v
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
