// Package strategies provides version extraction strategies and CNA pipelines for CVE 5.0 records.
package strategies

import (
	"strings"

	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
)

// VersionRangeType represents the type of versioning scheme for a range.
type VersionRangeType int

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

// ToVersionRangeType converts a string to a VersionRangeType.
func ToVersionRangeType(s string) VersionRangeType {
	switch strings.ToLower(s) {
	case "git":
		return VersionRangeTypeGit
	case "semver":
		return VersionRangeTypeSemver
	default:
		// Other version types like "custom" are treated as ecosystem ranges.
		return VersionRangeTypeEcosystem
	}
}

const acceptableQuality = vulns.Spaces

// VersionStrategy defines the contract for an individual version extraction strategy.
// Strategies are evaluated in the sequential order they appear in the configured slice.
type VersionStrategy interface {
	// Name returns a human-readable identifier for the strategy.
	Name() string
	// Extract attempts to extract OSV version ranges from a CVE5 Versions entry.
	// Returns the extracted ranges, the detected VersionRangeType, and true if this strategy handled the entry.
	Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) (ranges []models.RangeWithMetadata, vrt VersionRangeType, handled bool)
}
