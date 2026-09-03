package cve5

import (
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// StrategyPriority represents the execution precedence for version extraction strategies.
type StrategyPriority int

const (
	// PriorityFirst represents specialized or CNA-specific overrides that should be attempted before standard parsing (e.g., changes field, split range syntax).
	PriorityFirst StrategyPriority = 100

	// PriorityStandard represents standard structured CVE5 version range parsing rules that should always be attempted (e.g., lessThan/lessThanOrEqual, range expressions, git commits).
	PriorityStandard StrategyPriority = 200

	// PriorityLastResort represents heuristic or single-version fallbacks to be attempted only when standard range parsing cannot resolve the versions (e.g., 0-introduced, MITRE up-to, standalone single versions, text extraction).
	PriorityLastResort StrategyPriority = 300
)

// VersionStrategy defines the contract for an individual version extraction strategy.
type VersionStrategy interface {
	// Name returns a human-readable identifier for the strategy.
	Name() string
	// Priority returns the execution precedence of this strategy. Lower values run first.
	Priority() StrategyPriority
	// Extract attempts to extract OSV version ranges from a CVE5 Versions entry.
	// Returns the extracted ranges, the detected VersionRangeType, and true if this strategy handled the entry.
	Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) (ranges []models.RangeWithMetadata, vrt VersionRangeType, handled bool)
}

type prioritizedStrategy struct {
	VersionStrategy

	customPriority StrategyPriority
}

func (p *prioritizedStrategy) Priority() StrategyPriority {
	return p.customPriority
}

// WithPriority wraps an existing VersionStrategy with a customized priority level.
func WithPriority(strategy VersionStrategy, priority StrategyPriority) VersionStrategy {
	return &prioritizedStrategy{
		VersionStrategy: strategy,
		customPriority:  priority,
	}
}

// ChangesAtStrategy extracts the fixed version from the vers.Changes list when status is 'unaffected'.
//
// Resulting OSV Range: [introduced: "17.7.0", fixed: "17.7.2"]
type ChangesAtStrategy struct{}

func (s *ChangesAtStrategy) Name() string {
	return "ChangesAt"
}

func (s *ChangesAtStrategy) Priority() StrategyPriority {
	return PriorityFirst
}

func (s *ChangesAtStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	var fixedFromChanges string
	for _, ch := range vers.Changes {
		if ch.Status == "unaffected" && ch.At != "" {
			fixedFromChanges = ch.At
			break
		}
	}

	if fixedFromChanges == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Fixed from changes - %s", fixedFromChanges)
	var introduced string
	if vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		introduced = vers.Version
		metrics.AddNote("Introduced from version value - %s", vers.Version)
	}

	currentVersionType := toVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(introduced, "", fixedFromChanges)}

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}

// StandardRangeStrategy handles standard CVE 5.0 'lessThan' and 'lessThanOrEqual' range fields.
//
// Example CVE Record (CVE-2026-22104 - Hashtopolis):
//
//	{
//	    "version": "0",
//	    "lessThan": "0.14.8",
//	    "status": "affected",
//	    "versionType": "semver"
//	}
//
// Resulting OSV Range: [introduced: "0", fixed: "0.14.8"]
type StandardRangeStrategy struct{}

func (s *StandardRangeStrategy) Name() string {
	return "StandardRange"
}

func (s *StandardRangeStrategy) Priority() StrategyPriority {
	return PriorityStandard
}

func (s *StandardRangeStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	currentVersionType := toVersionRangeType(vers.VersionType)

	vQuality := vulns.CheckQuality(vers.Version)
	if !vQuality.AtLeast(acceptableQuality) {
		metrics.AddNote("Version value is filler or empty")
	}
	vLessThanQual := vulns.CheckQuality(vers.LessThan)
	vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

	hasRange := vLessThanQual.AtLeast(acceptableQuality) || vLTOEQual.AtLeast(acceptableQuality)

	// Handle cases where 'lessThan' or 'lessThanOrEqual' is mistakenly the same as 'version'.
	if vers.LessThan != "" && vers.LessThan == vers.Version {
		metrics.AddNote("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version)
		hasRange = false
	}
	if vers.LessThanOrEqual != "" && vers.LessThanOrEqual == vers.Version {
		metrics.AddNote("Warning: lessThanOrEqual (%s) is the same as introduced (%s)\n", vers.LessThanOrEqual, vers.Version)
		hasRange = false
	}

	if !hasRange {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Range detected: %v", hasRange)
	var introduced, fixed, lastaffected string
	if vQuality.AtLeast(acceptableQuality) {
		introduced = vers.Version
		metrics.AddNote("%s - Introduced from version value - %s", vQuality.String(), vers.Version)
	}

	if vLessThanQual.AtLeast(acceptableQuality) {
		fixed = vers.LessThan
		metrics.AddNote("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan)
	} else if vLTOEQual.AtLeast(acceptableQuality) {
		lastaffected = vers.LessThanOrEqual
		metrics.AddNote("%s - LastAffected from LessThanOrEqual value - %s", vLTOEQual.String(), vers.LessThanOrEqual)
	}

	var versionRanges []*osvschema.Range
	if fixed != "" {
		versionRanges = append(versionRanges, c.BuildVersionRange(introduced, "", fixed))
	} else if lastaffected != "" {
		versionRanges = append(versionRanges, c.BuildVersionRange(introduced, lastaffected, ""))
	}

	if len(versionRanges) == 0 {
		return nil, VersionRangeTypeUnknown, false
	}

	for _, vr := range versionRanges {
		if currentVersionType == VersionRangeTypeGit {
			vr.Type = osvschema.Range_GIT
			if affected.Repo != "" {
				vr.Repo = affected.Repo
			}
		}
	}

	return c.ToRangeWithMetadata(versionRanges, models.VersionSourceAffected), currentVersionType, true
}

// StringRangeExpressionStrategy handles range expressions embedded within the version field.
//
// Example CVE Record (CVE-2024-21634 - Puma / GitHub_M):
//
//	{
//	    "version": ">= 2.0, < 2.5",
//	    "status": "affected",
//	    "versionType": "semver"
//	}
//
// Resulting OSV Range: [introduced: "2.0", fixed: "2.5"]
type StringRangeExpressionStrategy struct{}

func (s *StringRangeExpressionStrategy) Name() string {
	return "StringRangeExpression"
}

func (s *StringRangeExpressionStrategy) Priority() StrategyPriority {
	return PriorityStandard
}

func (s *StringRangeExpressionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	av, err := git.ParseVersionRange(vers.Version)
	if err != nil || av.Introduced == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	currentVersionType := toVersionRangeType(vers.VersionType)
	var vr []*osvschema.Range
	if av.Fixed != "" {
		vr = append(vr, c.BuildVersionRange(av.Introduced, "", av.Fixed))
	} else if av.LastAffected != "" {
		vr = append(vr, c.BuildVersionRange(av.Introduced, av.LastAffected, ""))
	}

	if len(vr) == 0 {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Parsed range expression from version: %s", vers.Version)

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}

// GitCommitStrategy handles git commit versions by treating them as standalone git commits.
//
// Example CVE Record:
//
//	{
//	    "version": "deadbeefcafebabe0123456789abcdef01234567",
//	    "status": "affected",
//	    "versionType": "git"
//	}
//
// Resulting OSV Range: [introduced: "deadbeef...", last_affected: "deadbeef..."]
type GitCommitStrategy struct{}

func (s *GitCommitStrategy) Name() string {
	return "GitCommit"
}

func (s *GitCommitStrategy) Priority() StrategyPriority {
	return PriorityStandard
}

func (s *GitCommitStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}
	if toVersionRangeType(vers.VersionType) != VersionRangeTypeGit {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Git commit version found %v", vers.Version)
	vr := []*osvschema.Range{c.BuildGitVersionRange(vers.Version, vers.Version, "", affected.Repo)}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceGit)
	for i := range rwms {
		rwms[i].Metadata.Versions = []string{vers.Version}
	}

	return rwms, VersionRangeTypeGit, true
}

// GitCommitIntroducedOnlyStrategy treats a git commit version as an introduced-only point (used by Linux kernel).
//
// Example CVE Record (Linux Kernel git commits):
//
//	{
//	    "version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2",
//	    "status": "affected",
//	    "versionType": "git"
//	}
//
// Resulting OSV Range: [introduced: "1da177e4c..."]
type GitCommitIntroducedOnlyStrategy struct{}

func (s *GitCommitIntroducedOnlyStrategy) Name() string {
	return "GitCommitIntroducedOnly"
}

func (s *GitCommitIntroducedOnlyStrategy) Priority() StrategyPriority {
	return PriorityStandard
}

func (s *GitCommitIntroducedOnlyStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}
	if toVersionRangeType(vers.VersionType) != VersionRangeTypeGit {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Git commit introduced found %v", vers.Version)
	vr := []*osvschema.Range{c.BuildGitVersionRange(vers.Version, "", "", affected.Repo)}

	return c.ToRangeWithMetadata(vr, models.VersionSourceGit), VersionRangeTypeGit, true
}

// AffectedCPEStrategy extracts version ranges from CPE strings specified in affected.Cpes or version strings formatted as CPEs.
//
// Example CVE Record:
//
//	"affected": [
//	    {
//	        "cpes": ["cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"],
//	        "versions": [{ "status": "affected" }]
//	    }
//	]
//
// Resulting OSV Range: [introduced: "1.2.3", last_affected: "1.2.3"]
type AffectedCPEStrategy struct{}

func (s *AffectedCPEStrategy) Name() string {
	return "AffectedCPE"
}

func (s *AffectedCPEStrategy) Priority() StrategyPriority {
	return PriorityLastResort
}

func (s *AffectedCPEStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	cpeStr := ""
	if strings.HasPrefix(vers.Version, "cpe:") {
		cpeStr = vers.Version
	} else if len(affected.Cpes) > 0 {
		for _, cpe := range affected.Cpes {
			if strings.HasPrefix(cpe, "cpe:") {
				cpeStr = cpe
				break
			}
		}
	}

	if cpeStr == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	parsedCPE, err := c.ParseCPE(cpeStr)
	if err != nil || parsedCPE.Version == "" || parsedCPE.Version == "*" || parsedCPE.Version == "-" || parsedCPE.Version == "ANY" || parsedCPE.Version == "NA" {
		return nil, VersionRangeTypeUnknown, false
	}

	version := parsedCPE.Version
	if parsedCPE.Update != "" && parsedCPE.Update != "*" && parsedCPE.Update != "-" && parsedCPE.Update != "ANY" && parsedCPE.Update != "NA" {
		version += "." + parsedCPE.Update
	}

	if !vulns.CheckQuality(version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Extracted version %s from CPE %s", version, cpeStr)
	currentVersionType := toVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(version, version, "")}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceCPE)
	for i := range rwms {
		rwms[i].Metadata.CPE = cpeStr
		rwms[i].Metadata.Versions = []string{version}
	}

	return rwms, currentVersionType, true
}

// ZeroIntroducedSingleVersionStrategy treats a single version value (when only 1 version is listed)
// as spanning from 0 to that version (e.g. WPScan, Wordfence, Linux, or single-version MITRE records).
//
// Example CVE Record (CVE-2015-10001 - WPScan / Wordfence / MITRE):
//
//	{
//	    "version": "2.52",
//	    "status": "affected",
//	    "versionType": "custom"
//	}
//
// Resulting OSV Range: [introduced: "0", last_affected: "2.52"]
type ZeroIntroducedSingleVersionStrategy struct{}

func (s *ZeroIntroducedSingleVersionStrategy) Name() string {
	return "ZeroIntroducedSingleVersion"
}

func (s *ZeroIntroducedSingleVersionStrategy) Priority() StrategyPriority {
	return PriorityLastResort
}

func (s *ZeroIntroducedSingleVersionStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}
	if len(affected.Versions) > 1 {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Single version found %v - Assuming introduced = 0 and last affected = %v", vers.Version, vers.Version)
	currentVersionType := toVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange("0", vers.Version, "")}

	return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
}

// StandaloneSingleVersionStrategy treats a single version as an exact, standalone version (introduced == last_affected).
//
// Example CVE Record:
//
//	{
//	    "version": "1.0.0",
//	    "status": "affected"
//	}
//
// Resulting OSV Range: [introduced: "1.0.0", last_affected: "1.0.0"]
type StandaloneSingleVersionStrategy struct{}

func (s *StandaloneSingleVersionStrategy) Name() string {
	return "StandaloneSingleVersion"
}

func (s *StandaloneSingleVersionStrategy) Priority() StrategyPriority {
	return PriorityLastResort
}

func (s *StandaloneSingleVersionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Single version found %v - Treating as standalone version", vers.Version)
	currentVersionType := toVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, vers.Version, "")}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceAffected)
	for i := range rwms {
		rwms[i].Metadata.Versions = []string{vers.Version}
	}

	return rwms, currentVersionType, true
}

// SplitRangeStrategy handles split sequential version ranges
// (e.g. one entry with introduced and lessThan="unspecified", followed by an entry
// with version="unspecified" and lessThan/lessThanOrEqual).
//
// Example 1: Split Pair (CVE-2022-25929):
//
//	"versions": [
//	    { "version": "1.31.0", "lessThan": "unspecified", "status": "affected" },
//	    { "version": "unspecified", "lessThan": "1.36.1", "status": "affected" }
//	]
//	Resulting OSV Range: [introduced: "1.31.0", fixed: "1.36.1"]
//
// Example 2: Multi Split Sequences (CVE-2022-25761):
//
//	"versions": [
//	    { "version": "unspecified", "lessThan": "1.2.5", "status": "affected" },
//	    { "version": "1.3-rc1", "lessThan": "unspecified", "status": "affected" },
//	    { "version": "unspecified", "lessThan": "1.3.1", "status": "affected" }
//	]
//	Resulting OSV Ranges: [introduced: "0", fixed: "1.2.5"], [introduced: "1.3-rc1", fixed: "1.3.1"]
//
// Example 3: Standalone Upper Bound (CVE-2022-25865):
//
//	"versions": [
//	    { "version": "unspecified", "lessThan": "0.18.4", "status": "affected" }
//	]
//	Resulting OSV Range: [introduced: "0", fixed: "0.18.4"]
type SplitRangeStrategy struct{}

func (s *SplitRangeStrategy) Name() string {
	return "SplitRange"
}

func (s *SplitRangeStrategy) Priority() StrategyPriority {
	return PriorityFirst
}

func isExplicitUnspecified(val string) bool {
	clean := strings.TrimSpace(strings.ToLower(val))

	return clean == "unspecified"
}

func isValidSplitVersion(val string) bool {
	clean := strings.TrimSpace(strings.ToLower(val))
	if clean == "" || clean == "unspecified" || clean == "n/a" || clean == "na" || clean == "*" || clean == "-" {
		return false
	}

	return vulns.CheckQuality(val).AtLeast(acceptableQuality) || val == "0"
}

func isSplitIntroducedOnly(v models.Versions) bool {
	return isValidSplitVersion(v.Version) && (isExplicitUnspecified(v.LessThan) || isExplicitUnspecified(v.LessThanOrEqual))
}

func isSplitUpperBoundOnly(v models.Versions) bool {
	return isExplicitUnspecified(v.Version) && (isValidSplitVersion(v.LessThan) || isValidSplitVersion(v.LessThanOrEqual))
}

func (s *SplitRangeStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}

	// Check for "unspecified" split or standalone ranges across affected.Versions
	idx := -1
	for i, v := range affected.Versions {
		if v.Version == vers.Version && v.LessThan == vers.LessThan && v.LessThanOrEqual == vers.LessThanOrEqual && v.Status == vers.Status && v.VersionType == vers.VersionType {
			idx = i
			break
		}
	}

	// Case A: Introduced-only entry (e.g. {version: "1.31.0", lessThan: "unspecified"})
	if isSplitIntroducedOnly(vers) {
		currentVersionType := toVersionRangeType(vers.VersionType)
		// Check if the immediately following entry is an upper-bound entry
		if idx >= 0 && idx+1 < len(affected.Versions) && isSplitUpperBoundOnly(affected.Versions[idx+1]) {
			nextVers := affected.Versions[idx+1]
			var fixed, lastAffected string
			if isValidSplitVersion(nextVers.LessThan) {
				fixed = nextVers.LessThan
			} else if isValidSplitVersion(nextVers.LessThanOrEqual) {
				lastAffected = nextVers.LessThanOrEqual
			}

			vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, lastAffected, fixed)}
			metrics.AddNote("Parsed split range: introduced %s, upper bound %s%s", vers.Version, fixed, lastAffected)

			return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
		}

		// Standalone introduced entry without a following upper bound
		vr := []*osvschema.Range{c.BuildVersionRange(vers.Version, "", "")}
		metrics.AddNote("Parsed standalone introduced version: %s", vers.Version)

		return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
	}

	// Case B: Upper-bound-only entry (e.g. {version: "unspecified", lessThan: "1.36.1"})
	if isSplitUpperBoundOnly(vers) {
		currentVersionType := toVersionRangeType(vers.VersionType)
		// If preceded by an introduced-only entry, it was already paired and consumed in Case A
		if idx > 0 && isSplitIntroducedOnly(affected.Versions[idx-1]) {
			return nil, currentVersionType, true
		}

		// Standalone upper bound starting from 0
		var fixed, lastAffected string
		if isValidSplitVersion(vers.LessThan) {
			fixed = vers.LessThan
		} else if isValidSplitVersion(vers.LessThanOrEqual) {
			lastAffected = vers.LessThanOrEqual
		}

		vr := []*osvschema.Range{c.BuildVersionRange("0", lastAffected, fixed)}
		metrics.AddNote("Parsed upper-bound range with introduced=0: %s%s", fixed, lastAffected)

		return c.ToRangeWithMetadata(vr, models.VersionSourceAffected), currentVersionType, true
	}

	return nil, VersionRangeTypeUnknown, false
}

// VersionTextExtractionStrategy handles natural text version patterns.
//
// Example CVE Record:
//
//	{
//	    "version": "Fixed in version 2.4.1 and higher",
//	    "status": "affected"
//	}
type VersionTextExtractionStrategy struct{}

func (s *VersionTextExtractionStrategy) Name() string {
	return "VersionTextExtraction"
}

func (s *VersionTextExtractionStrategy) Priority() StrategyPriority {
	return PriorityLastResort
}

func (s *VersionTextExtractionStrategy) Extract(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" || vers.Version == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	possibleVersions := c.ExtractVersionsFromText(nil, vers.Version, metrics, models.VersionSourceAffected)
	if possibleVersions != nil {
		metrics.AddNote("Versions retrieved from text but not used CURRENTLY")
	}

	return nil, VersionRangeTypeUnknown, false
}

// CPEVersionStrategy extracts version ranges from the CVE's CPE applicability statements.
//
// Example CVE Record:
//
//	"cpeApplicability": [
//	    {
//	        "nodes": [{
//	            "operator": "OR",
//	            "cpeMatch": [{
//	                "vulnerable": true,
//	                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
//	                "versionStartIncluding": "1.0.0",
//	                "versionEndExcluding": "2.0.0"
//	            }]
//	        }]
//	    }
//	]
//
// Resulting OSV Range: [introduced: "1.0.0", fixed: "2.0.0"]
type CPEVersionStrategy struct{}

func (s *CPEVersionStrategy) Name() string {
	return "CPEApplicability"
}

func (s *CPEVersionStrategy) Priority() StrategyPriority {
	return PriorityStandard
}

func (s *CPEVersionStrategy) Extract(cve models.CVE5, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, error) {
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err == nil && len(cpeRanges) > 0 {
		metrics.AddNote("Strategy successful: %s", s.Name())
		metrics.VersionSources = append(metrics.VersionSources, models.VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)

		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNote("%s", err.Error())
	}

	return nil, err
}

// Strategy Pipeline Presets for different CNAs

func DefaultStrategies() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&VersionTextExtractionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func GitHubStrategies() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func WPScanStrategies() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func WordfenceStrategies() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func PatchstackStrategies() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func MITREStrategies() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func LinuxStrategies() []VersionStrategy {
	return []VersionStrategy{
		&StandardRangeStrategy{},
		&GitCommitIntroducedOnlyStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func cpeVersionExtraction(cve models.CVE5, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, error) {
	return (&CPEVersionStrategy{}).Extract(cve, metrics)
}
