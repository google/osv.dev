package cvelist2osv

import (
	"cmp"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility/logger"
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

// VersionSource indicates the source of the extracted version information.
type VersionSource string

const (
	VersionSourceNone        VersionSource = "NOVERS"
	VersionSourceAffected    VersionSource = "CVEAFFVERS"
	VersionSourceGit         VersionSource = "GITVERS"
	VersionSourceCPE         VersionSource = "CPEVERS"
	VersionSourceDescription VersionSource = "DESCRVERS"
)

type ConversionOutcome int

const (
	// Set of enums for categorizing conversion outcomes.
	ConversionUnknown ConversionOutcome = iota // Shouldn't happen
	Successful                                 // It worked!
	Rejected                                   // The CVE was rejected
	NoSoftware                                 // The CVE had no CPEs relating to software (i.e. Operating Systems or Hardware).
	NoRepos                                    // The CPE Vendor/Product had no repositories derived for it.
	NoCommitRanges                             // No viable commit ranges could be calculated from the repository for the CVE's CPE(s).
	NoRanges                                   // No version ranges could be extracted from the record.
	FixUnresolvable                            // Partial resolution of versions, resulting in a false positive.
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

// resolveVersionToCommit is a helper to convert a version string to a commit hash.
// It logs the outcome of the conversion attempt and returns an empty string on failure.
func resolveVersionToCommit(cveID cves.CVEID, version, versionType, repo string, normalizedTags map[string]git.NormalizedTag) string {
	if version == "" {
		return ""
	}
	logger.Info("Attempting to resolve version to commit", slog.String("cve", string(cveID)), slog.String("version", version), slog.String("type", versionType), slog.String("repo", repo))
	commit, err := git.VersionToCommit(version, normalizedTags)
	if err != nil {
		logger.Warn("Failed to get Git commit for version", slog.String("cve", string(cveID)), slog.String("version", version), slog.String("type", versionType), slog.String("repo", repo))
		return ""
	}
	logger.Info("Successfully derived commit for version", slog.String("cve", string(cveID)), slog.String("commit", commit), slog.String("version", version), slog.String("type", versionType))

	return commit
}

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), VersionInfo with AffectedVersions and
// typically no AffectedCommits and attempts to add AffectedCommits (including Fixed commits) where there aren't any.
// Refuses to add the same commit to AffectedCommits more than once.
func gitVersionsToCommits(cveID cves.CVEID, versionRanges []osvschema.Range, repos []string, metrics *ConversionMetrics, cache git.RepoTagsCache) (osvschema.Affected, error) {
	var newAff osvschema.Affected
	var newVersionRanges []osvschema.Range
	unresolvedRanges := versionRanges

	for _, repo := range repos {
		if len(unresolvedRanges) == 0 {
			break // All ranges have been resolved.
		}

		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			metrics.AddNote("Failed to normalize tags - %s", repo)
			continue
		}

		var stillUnresolvedRanges []osvschema.Range
		for _, vr := range unresolvedRanges {
			var introduced, fixed, lastAffected string
			for _, e := range vr.Events {
				if e.Introduced != "" {
					introduced = e.Introduced
				}
				if e.Fixed != "" {
					fixed = e.Fixed
				}
				if e.LastAffected != "" {
					lastAffected = e.LastAffected
				}
			}

			var introducedCommit string
			if introduced == "0" {
				introducedCommit = "0"
			} else {
				introducedCommit = resolveVersionToCommit(cveID, introduced, "introduced", repo, normalizedTags)
			}
			fixedCommit := resolveVersionToCommit(cveID, fixed, "fixed", repo, normalizedTags)
			lastAffectedCommit := resolveVersionToCommit(cveID, lastAffected, "last_affected", repo, normalizedTags)

			if introducedCommit != "" && (fixedCommit != "" || lastAffectedCommit != "") {
				var newVR osvschema.Range

				if fixedCommit != "" {
					newVR = cves.BuildVersionRange(introducedCommit, "", fixedCommit)
				} else {
					newVR = cves.BuildVersionRange(introducedCommit, lastAffectedCommit, "")
				}

				newVR.Repo = repo
				newVR.Type = osvschema.RangeGit
				newVR.DatabaseSpecific = make(map[string]any)
				newVR.DatabaseSpecific["versions"] = vr.Events
				newVersionRanges = append(newVersionRanges, newVR)
			} else {
				stillUnresolvedRanges = append(stillUnresolvedRanges, vr)
			}
		}
		unresolvedRanges = stillUnresolvedRanges
	}

	var err error
	if len(unresolvedRanges) > 0 {
		newAff.DatabaseSpecific = make(map[string]any)
		newAff.DatabaseSpecific["unresolved_versions"] = unresolvedRanges
		metrics.UnresolvedRangesCount += len(unresolvedRanges)
	}

	if len(newVersionRanges) > 0 {
		newAff.Ranges = newVersionRanges
		metrics.ResolvedRangesCount += len(newVersionRanges)
	} else if len(unresolvedRanges) > 0 { // Only error if there were ranges to resolve but none were.
		err = errors.New("was not able to get git version ranges")
	}

	return newAff, err
}

// findCPEVersionRanges extracts version ranges and CPE strings from the CNA's
// CPE applicability statements in a CVE record.
func findCPEVersionRanges(cve cves.CVE5) (versionRanges []osvschema.Range, cpes []string, err error) {
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
