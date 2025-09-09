package cvelist2osv

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
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

// AddVersionInfo attempts to extract version information from a CVE and add it to the OSV record.
// It follows a prioritized approach:
// 1. For Linux kernel CVEs, it specifically looks for CPE version ranges.
// 2. It processes the 'affected' fields from both the CNA and ADP containers.
// 3. If no versions are found, it falls back to searching for CPEs in the CNA container.
// 4. As a last resort, it attempts to extract version information from the description text (currently not saved).
// It returns the source of the version information and a slice of notes detailing the extraction process.
func AddVersionInfo(cve cves.CVE5, v *vulns.Vulnerability) ([]VersionSource, []string) {
	var notes []string
	var source []VersionSource
	gotVersions := false

	// Combine 'affected' entries from both CNA and ADP containers.
	cna := cve.Containers.CNA
	adps := cve.Containers.ADP

	affected := cna.Affected
	for _, adp := range adps {
		if adp.Affected != nil {
			affected = append(affected, adp.Affected...)
		}
	}

	// Attempt to extract version ranges from the combined 'affected' fields.
	hasGit := false
	for _, cveAff := range affected {
		versionRanges, versionType, extractNotes := extractVersionsFromAffectedField(cveAff, cve.Metadata.AssignerShortName)
		// TODO(jesslowe): update this to be more elegant (currently skips retrieving more git ranges after the first)
		if versionType == VersionRangeTypeGit && hasGit {
			continue
		}
		notes = append(notes, extractNotes...)

		if len(versionRanges) == 0 {
			continue
		}

		gotVersions = true
		if versionType == VersionRangeTypeGit {
			hasGit = true
		}

		aff := osvschema.Affected{}
		for _, vr := range versionRanges {
			if versionType == VersionRangeTypeGit {
				vr.Type = osvschema.RangeGit
				vr.Repo = cveAff.Repo
			} else {
				vr.Type = osvschema.RangeEcosystem
			}
			aff.Ranges = append(aff.Ranges, vr)
		}

		// Special handling for Linux kernel CVEs.
		if cve.Metadata.AssignerShortName == "Linux" && versionType != VersionRangeTypeGit {
			aff.Package = osvschema.Package{
				Ecosystem: string(osvschema.EcosystemLinux),
				Name:      "Kernel",
			}
		}

		v.Affected = append(v.Affected, aff)
		if hasGit {
			source = append(source, VersionSourceGit)
		} else {
			source = append(source, VersionSourceAffected)
		}
	}

	// If no versions were found so far, fall back to CPEs.
	if !gotVersions {
		notes = append(notes, "No versions in affected, attempting to extract from CPE")
		cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
		if err == nil && len(cpeRanges) > 0 {
			gotVersions = true
			source = append(source, VersionSourceCPE)
			aff := osvschema.Affected{}
			for _, vr := range cpeRanges {
				vr.Type = osvschema.RangeEcosystem
				aff.Ranges = append(aff.Ranges, vr)
			}
			aff.DatabaseSpecific = make(map[string]any)
			aff.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
			v.Affected = append(v.Affected, aff)
		} else if err != nil {
			notes = append(notes, err.Error())
		}
	}

	// As a last resort, try extracting versions from the description text.
	if !gotVersions {
		notes = append(notes, "No versions in CPEs so attempting extraction from description")
		versions, extractNotes := cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
		notes = append(notes, extractNotes...)
		if len(versions) > 0 {
			// NOTE: These versions are not currently saved due to the need for better validation.
			source = append(source, VersionSourceDescription)
			notes = append(notes, fmt.Sprintf("Extracted versions from description but did not save them: %+v", versions))
		}
	}

	return source, notes
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
					versionRanges = append(versionRanges, buildVersionRange(match.VersionStartIncluding, "", match.VersionEndExcluding))
				} else if match.VersionEndIncluding != "" {
					versionRanges = append(versionRanges, buildVersionRange(match.VersionStartIncluding, match.VersionEndIncluding, ""))
				}
			}
		}
	}
	if len(versionRanges) == 0 {
		return nil, nil, errors.New("no versions extracted from CPEs")
	}

	return versionRanges, cpes, nil
}

// extractVersionsFromAffectedField extracts version ranges from a CVE 'affected' entry.
// It handles various scenarios:
// - If `defaultStatus` is "affected", it may calculate the inverse ranges (common for Linux).
// - It iterates through `versions` entries with `status: "affected"`.
// - It constructs ranges from `version`, `lessThan`, and `lessThanOrEqual` fields.
// - For GitHub CVEs, it uses a special parser for version strings like "< 1.2.3".
// - For git commits, it creates an introduced event.
// - As a fallback, it may assume a single version means "fixed at this version, introduced at 0".
//
// Returns the extracted OSV ranges, the most frequent version type (e.g., "semver"), and any notes.
func extractVersionsFromAffectedField(affected cves.Affected, cnaAssigner string) ([]osvschema.Range, VersionRangeType, []string) {
	// Handle cases where a product is marked as "affected" by default, and specific versions are marked "unaffected".
	if affected.DefaultStatus == "affected" {
		// Calculate the affected ranges by finding the inverse of the unaffected ranges.
		return findInverseAffectedRanges(affected, cnaAssigner)
	}

	return findNormalAffectedRanges(affected, cnaAssigner)
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. This is common in Linux kernel CVEs where a product is
// considered affected by default, and only unaffected versions are listed.
// It sorts the introduced and fixed versions to create chronological ranges.
func findInverseAffectedRanges(cveAff cves.Affected, cnaAssigner string) (ranges []osvschema.Range, versType VersionRangeType, notes []string) {
	if cnaAssigner != "Linux" {
		return nil, VersionRangeTypeUnknown, append(notes, "Currently only supporting Linux inverse logic")
	}
	var introduced []string
	fixed := make([]string, 0, len(cveAff.Versions))
	for _, vers := range cveAff.Versions {
		versionValue := vers.Version
		if vers.Status == "affected" {
			if len(strings.Split(versionValue, ".")) != 3 {
				introduced = append(introduced, versionValue+".0")
			} else {
				introduced = append(introduced, versionValue)
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
			ranges = append(ranges, buildVersionRange(introduced[index], "", f))
			notes = append(notes, "Introduced from version value - "+introduced[index])
			notes = append(notes, "Fixed from version value - "+f)
		}
	}

	if len(ranges) != 0 {
		return ranges, VersionRangeTypeSemver, notes
	}
	notes = append(notes, "no ranges found")

	return nil, VersionRangeTypeUnknown, notes
}

func findNormalAffectedRanges(affected cves.Affected, cnaAssigner string) (versionRanges []osvschema.Range, versType VersionRangeType, notes []string) {
	versionTypesCount := make(map[VersionRangeType]int)

	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}

		currentVersionType := toVersionRangeType(vers.VersionType)
		versionTypesCount[currentVersionType]++

		var introduced, fixed, lastaffected string

		// Quality check the version strings to avoid using filler content.
		vQuality := vulns.CheckQuality(vers.Version)
		if !vQuality.AtLeast(acceptableQuality) {
			notes = append(notes, fmt.Sprintf("Version value for %s %s is filler or empty", affected.Vendor, affected.Product))
		}
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasRange := vLessThanQual.AtLeast(acceptableQuality) || vLTOEQual.AtLeast(acceptableQuality)
		notes = append(notes, fmt.Sprintf("Range detected: %v", hasRange))
		// Handle cases where 'lessThan' is mistakenly the same as 'version'.
		if vers.LessThan != "" && vers.LessThan == vers.Version {
			notes = append(notes, fmt.Sprintf("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version))
			hasRange = false
		}

		if hasRange {
			if vQuality.AtLeast(acceptableQuality) {
				introduced = vers.Version
				notes = append(notes, fmt.Sprintf("%s - Introduced from version value - %s", vQuality.String(), vers.Version))
			}
			if vLessThanQual.AtLeast(acceptableQuality) {
				fixed = vers.LessThan
				notes = append(notes, fmt.Sprintf("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan))
			} else if vLTOEQual.AtLeast(acceptableQuality) {
				lastaffected = vers.LessThanOrEqual
				notes = append(notes, fmt.Sprintf("%s - LastAffected from LessThanOrEqual value- %s", vLTOEQual.String(), vers.LessThanOrEqual))
			}

			if introduced != "" && fixed != "" {
				versionRanges = append(versionRanges, buildVersionRange(introduced, "", fixed))
			} else if introduced != "" && lastaffected != "" {
				versionRanges = append(versionRanges, buildVersionRange(introduced, lastaffected, ""))
			}

			continue
		}

		// In this case only vers.Version exists which either means that it is _only_ that version that is
		// affected, but more likely, it affects up to that version. It could also mean that the range is given
		// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.
		notes = append(notes, "Only version exists")
		// GitHub often encodes the range directly in the version string.
		if cnaAssigner == "GitHub_M" {
			av, err := git.ParseVersionRange(vers.Version)
			if err == nil {
				if av.Introduced == "" {
					continue
				}
				if av.Fixed != "" {
					versionRanges = append(versionRanges, buildVersionRange(av.Introduced, "", av.Fixed))
				} else if av.LastAffected != "" {
					versionRanges = append(versionRanges, buildVersionRange(av.Introduced, av.LastAffected, ""))
				}
			}

			continue
		}

		if currentVersionType == VersionRangeTypeGit {
			versionRanges = append(versionRanges, buildVersionRange(vers.Version, "", ""))
			continue
		}

		// Try to extract versions from text like "before 1.4.7".
		possibleVersions, note := cves.ExtractVersionsFromText(nil, vers.Version)
		if note != nil {
			notes = append(notes, note...)
		}
		if possibleVersions != nil {
			notes = append(notes, "Versions retrieved from text but not used CURRENTLY")
			continue
		}

		// As a fallback, assume a single version means it's the fixed version.
		if vQuality.AtLeast(acceptableQuality) {
			versionRanges = append(versionRanges, buildVersionRange("0", "", vers.Version))
			notes = append(notes, fmt.Sprintf("%s - Single version found %v - Assuming introduced = 0 and Fixed = %v", vQuality, vers.Version, vers.Version))
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

	return versionRanges, mostFrequentVersionType, notes
}

// buildVersionRange is a helper function that adds 'introduced', 'fixed', or 'last_affected'
// events to an OSV version range. If 'intro' is empty, it defaults to "0".
func buildVersionRange(intro string, lastAff string, fixed string) osvschema.Range {
	var versionRange osvschema.Range
	var i string
	if intro == "" {
		i = "0"
	} else {
		i = intro
	}
	versionRange.Events = append(versionRange.Events, osvschema.Event{
		Introduced: i})

	if fixed != "" {
		versionRange.Events = append(versionRange.Events, osvschema.Event{
			Fixed: fixed})
	} else if lastAff != "" {
		versionRange.Events = append(versionRange.Events, osvschema.Event{
			LastAffected: lastAff,
		})
	}

	return versionRange
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
	longerParts := partsB
	result := -1 // Assume 'b' is greater
	if len(partsA) > len(partsB) {
		longerParts = partsA
		result = 1 // 'a' is actually greater
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
