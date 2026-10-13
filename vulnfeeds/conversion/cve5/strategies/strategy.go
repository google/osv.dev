// Package strategies provides version extraction strategies and CNA pipelines for CVE 5.0 records.
package strategies

import (
	"cmp"
	"strconv"
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

// ExtractionState encapsulates the immutable Affected block, consumed version tracking,
// and accumulated extracted ranges so strategies cannot mark version indices as consumed
// without emitting corresponding ranges.
type ExtractionState struct {
	Affected models.Affected
	consumed []bool
	ranges   []models.RangeWithMetadata
}

// NewExtractionState initializes a new ExtractionState for the given Affected block.
func NewExtractionState(affected models.Affected) *ExtractionState {
	return &ExtractionState{
		Affected: affected,
		consumed: make([]bool, len(affected.Versions)),
	}
}

// IsConsumed reports whether the version entry at index i has already been handled.
func (s *ExtractionState) IsConsumed(i int) bool {
	return s.consumed[i]
}

// AllConsumed reports whether every version entry in s.Affected.Versions has been handled.
func (s *ExtractionState) AllConsumed() bool {
	for _, c := range s.consumed {
		if !c {
			return false
		}
	}

	return true
}

// Emit atomically marks the given version indices as consumed and appends ranges to the state.
// If ranges is empty, Emit is a no-op.
func (s *ExtractionState) Emit(ranges []models.RangeWithMetadata, indices ...int) {
	if len(ranges) == 0 {
		return
	}
	for _, idx := range indices {
		s.consumed[idx] = true
	}
	s.ranges = append(s.ranges, ranges...)
}

// EmitAll atomically marks all version entries in s.Affected.Versions as consumed and appends ranges.
// If ranges is empty, EmitAll is a no-op.
func (s *ExtractionState) EmitAll(ranges []models.RangeWithMetadata) {
	if len(ranges) == 0 {
		return
	}
	for i := range s.consumed {
		s.consumed[i] = true
	}
	s.ranges = append(s.ranges, ranges...)
}

// Ranges returns all extracted ranges accumulated so far.
func (s *ExtractionState) Ranges() []models.RangeWithMetadata {
	return s.ranges
}

// SetStrategyFrom assigns strategyName to the Metadata.Strategy field for all ranges starting from startIdx.
func (s *ExtractionState) SetStrategyFrom(startIdx int, strategyName string) {
	for i := startIdx; i < len(s.ranges); i++ {
		if s.ranges[i].Metadata.Strategy == "" {
			s.ranges[i].Metadata.Strategy = strategyName
		}
	}
}

// VersionStrategy defines the contract for an Affected-level version extraction strategy.
// Strategies are evaluated in the sequential order they appear in the configured slice.
type VersionStrategy interface {
	// Name returns a human-readable identifier for the strategy.
	Name() string
	// Extract attempts to extract OSV version ranges from state.Affected,
	// skipping entries where state.IsConsumed(i) is true and recording extracted ranges
	// via state.Emit or state.EmitAll.
	Extract(state *ExtractionState, metrics *models.ConversionMetrics)
}

// VersionExtractorFunc is the signature for strategies that inspect one models.Versions entry at a time.
type VersionExtractorFunc func(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, bool)

// ExtractPerVersion applies a single-version extraction function across unconsumed entries in state.Affected.Versions,
// emitting handled entries to state.
func ExtractPerVersion(state *ExtractionState, metrics *models.ConversionMetrics, fn VersionExtractorFunc) {
	for i, vers := range state.Affected.Versions {
		if state.IsConsumed(i) {
			continue
		}
		ranges, handled := fn(vers, state.Affected, metrics)
		if handled {
			state.Emit(ranges, i)
		}
	}
}

// CompareSemverLike provides a custom comparison function for version strings that may not
// strictly adhere to the SemVer specification. It compares versions numerically,
// part by part (major, minor, patch).
func CompareSemverLike(a, b string) int {
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
	if len(partsA) > len(partsB) {
		longerParts = partsA
		result = 1
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
