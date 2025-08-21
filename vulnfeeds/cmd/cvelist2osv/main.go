package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/exp/slices"
)

const (
	extension = ".json"
)

var (
	jsonPath = flag.String("cve_json", "", "Path to CVEList JSON to examine.")
	outDir   = flag.String("out_dir", "", "Path to output results.")
)

var Logger utility.LoggerWrapper

// Metrics holds the collected data about the conversion process for a single CVE.
var Metrics struct {
	CNA           string                          // The CNA that assigned the CVE.
	Outcome       string                          // The final outcome of the conversion (e.g., "Successful", "Failed").
	Repos         []string                        // A list of repositories extracted from the CVE's references.
	RefTypesCount map[osvschema.ReferenceType]int // A count of each type of reference found.
	Notes         []string                        // A collection of notes and warnings generated during conversion.
}

// RefTagDenyList contains reference tags that are often associated with unreliable or
// irrelevant repository URLs. References with these tags are currently ignored
// to avoid incorrect repository associations.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these.
}

// extractConversionMetrics examines a CVE and its generated OSV references to populate
// the global Metrics struct with heuristics about the conversion process.
// It captures the assigning CNA and counts the occurrences of each reference type.
func extractConversionMetrics(cve cves.CVE5, refs []osvschema.Reference) {
	// Capture the CNA for heuristic analysis.
	Metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis

	// Count number of references of each type
	refTypeCounts := make(map[osvschema.ReferenceType]int)
	for _, ref := range refs {
		refTypeCounts[ref.Type]++
	}
	Metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		Metrics.Notes = append(Metrics.Notes, fmt.Sprintf("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count))
	}

	// TODO(jesslowe): Add more analysis based on ADP containers, CVSS, KEV, CWE, etc.
}

// AddVersionInfo attempts to extract version information from a CVE and add it to the OSV record.
// It follows a prioritized approach:
// 1. For Linux kernel CVEs, it specifically looks for CPE version ranges.
// 2. It processes the 'affected' fields from both the CNA and ADP containers.
// 3. If no versions are found, it falls back to searching for CPEs in the CNA container.
// 4. As a last resort, it attempts to extract version information from the description text (currently not saved).
// It returns a slice of notes detailing the extraction process.
func AddVersionInfo(cve cves.CVE5, v *vulns.Vulnerability) []string {
	var notes []string
	// Special handling for Linux kernel CVEs, prioritizing CPEs for version info.
	if cve.Metadata.AssignerShortName == "Linux" {
		pkg := osvschema.Package{
			Ecosystem: string(osvschema.EcosystemLinux),
			Name:      "Kernel",
		}

		cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
		if err != nil {
			notes = append(notes, err.Error())
		}
		if cpeRanges != nil {
			affected := osvschema.Affected{
				Package: pkg,
			}
			for _, r := range cpeRanges {
				r.Type = osvschema.RangeEcosystem
				affected.Ranges = append(affected.Ranges, r)
			}
			affected.DatabaseSpecific = make(map[string]interface{})
			affected.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
			v.Affected = append(v.Affected, affected)
		}
	}

	// Combine 'affected' entries from both CNA and ADP containers.
	cna := cve.Containers.CNA
	adps := cve.Containers.ADP
	gotVersions := false

	affected := cna.Affected
	for _, adp := range adps {
		if adp.Affected != nil {
			affected = append(affected, adp.Affected...)
		}
	}

	// Attempt to extract version ranges from the combined 'affected' fields.
	for _, cveAff := range affected {
		versionRanges, versionType, extractNotes := ExtractVersionsFromAffectedField(cveAff, cve.Metadata.AssignerShortName)
		notes = append(notes, extractNotes...)
		if len(versionRanges) == 0 {
			continue
		}
		gotVersions = true

		if versionType == "git" {
			affected := osvschema.Affected{}
			for _, vr := range versionRanges {
				vr.Type = osvschema.RangeGit
				vr.Repo = cveAff.Repo
				affected.Ranges = append(affected.Ranges, vr)
			}
			v.Affected = append(v.Affected, affected)
		} else {
			affected := osvschema.Affected{}
			for _, vr := range versionRanges {
				vr.Type = osvschema.RangeEcosystem
				affected.Ranges = append(affected.Ranges, vr)
			}
			// Special handling for Linux kernel CVEs.
			if cve.Metadata.AssignerShortName == "Linux" {
				affected.Package = osvschema.Package{
					Ecosystem: string(osvschema.EcosystemLinux),
					Name:      "Kernel",
				}
			}
			v.Affected = append(v.Affected, affected)
		}
	}

	// If no versions were found in 'affected', fall back to CPEs.
	if !gotVersions {
		notes = append(notes, "No versions in affected, attempting to extract from CPE")
		cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
		if err != nil {
			notes = append(notes, err.Error())
		}
		if len(cpeRanges) != 0 {
			affected := osvschema.Affected{}
			for _, vr := range cpeRanges {
				vr.Type = osvschema.RangeEcosystem
				affected.Ranges = append(affected.Ranges, vr)
			}
			affected.DatabaseSpecific = make(map[string]interface{})
			affected.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
			v.Affected = append(v.Affected, affected)
		}
	}

	// As a last resort, try extracting versions from the description text.
	if !gotVersions {
		notes = append(notes, "No versions in CPEs so attempting extraction from description")
		versions, extractNotes := cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
		notes = append(notes, extractNotes...)
		if len(versions) > 0 {
			// NOTE: These versions are not currently saved due to the need for better validation.
			notes = append(notes, fmt.Sprintf("Extracted versions from description but did not save them: %+v", versions))
		}
	}

	return notes
}

// buildVersionRange is a helper function that adds 'introduced', 'fixed', or 'last_affected'
// events to an OSV version range. If 'intro' is empty, it defaults to "0".
func buildVersionRange(intro string, lastAff string, fixed string) (versionRange osvschema.Range) {
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
		return nil, nil, fmt.Errorf("no versions extracted from CPEs")
	}
	return versionRanges, cpes, nil
}

// ExtractVersionsFromAffectedField extracts version ranges from a CVE 'affected' entry.
// It handles various scenarios:
// - If `defaultStatus` is "affected", it may calculate the inverse ranges (common for Linux).
// - It iterates through `versions` entries with `status: "affected"`.
// - It constructs ranges from `version`, `lessThan`, and `lessThanOrEqual` fields.
// - For GitHub CVEs, it uses a special parser for version strings like "< 1.2.3".
// - For git commits, it creates an introduced event.
// - As a fallback, it may assume a single version means "fixed at this version, introduced at 0".
//
// Returns the extracted OSV ranges, the most frequent version type (e.g., "semver"), and any notes.
func ExtractVersionsFromAffectedField(affected cves.Affected, cnaAssigner string) (versionRanges []osvschema.Range, rangeType string, notes []string) {

	// Handle cases where a product is marked as "affected" by default, and specific versions are marked "unaffected".
	if affected.DefaultStatus == "affected" {
		// For Linux kernel CVEs, this logic is often handled by CPEs, so we skip it here.
		if cnaAssigner == "Linux" {
			notes = append(notes, "Skipping Linux Affected range versions in favour of CPE versions")
			return nil, "", notes
		}
		// Calculate the affected ranges by finding the inverse of the unaffected ranges.
		ranges, inverseNotes := findInverseAffectedRanges(affected, cnaAssigner)
		notes = append(notes, inverseNotes...)

		if len(ranges) != 0 {
			return ranges, string(osvschema.RangeSemVer), notes
		}
		return nil, "", notes
	}

	return findNormalAffectedRanges(affected, cnaAssigner)

}

// sortBadSemver provides a custom sorting function for version strings that may not
// strictly adhere to the SemVer specification. It compares versions numerically,
// part by part (major, minor, patch).
func sortBadSemver(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	majorA, _ := strconv.Atoi(partsA[0])
	majorB, _ := strconv.Atoi(partsB[0])

	if c := cmp.Compare(majorA, majorB); c != 0 {
		return c
	}

	minorA, _ := strconv.Atoi(partsA[1])
	minorB, _ := strconv.Atoi(partsB[1])
	if c := cmp.Compare(minorA, minorB); c != 0 {
		return c
	}
	patchA, _ := strconv.Atoi(partsA[2])
	patchB, _ := strconv.Atoi(partsB[2])
	return cmp.Compare(patchA, patchB)
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. This is common in Linux kernel CVEs where a product is
// considered affected by default, and only unaffected versions are listed.
// It sorts the introduced and fixed versions to create chronological ranges.
func findInverseAffectedRanges(cveAff cves.Affected, cnaAssigner string) (ranges []osvschema.Range, notes []string) {
	if cnaAssigner != "Linux" {
		return nil, append(notes, "Currently only supporting Linux inverse logic")
	}
	var introduced []string
	var fixed []string
	for _, vers := range cveAff.Versions {
		if vers.Status == "affected" {
			introduced = append(introduced, vers.Version)
		}
		if vers.Status != "unaffected" {
			continue
		}

		if vers.Version == "0" || vers.VersionType != "semver" {
			continue
		}
		fixed = append(fixed, vers.Version)
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

	slices.SortFunc(introduced, sortBadSemver)
	slices.SortFunc(fixed, sortBadSemver)

	// If the first fixed version is earlier than the first introduced, assume introduction from "0".
	if len(fixed) > 0 && len(introduced) > 0 && fixed[0] < introduced[0] {
		introduced = append([]string{"0"}, introduced...)
	}

	// Create ranges by pairing sorted introduced and fixed versions.
	for index, f := range fixed {
		if index < len(introduced) {
			ranges = append(ranges, buildVersionRange(introduced[index], "", f))
			notes = append(notes, fmt.Sprintf("Introduced from version value - %s", introduced[index]))
			notes = append(notes, fmt.Sprintf("Fixed from version value - %s", f))
		}
	}

	return ranges, notes
}

func findNormalAffectedRanges(affected cves.Affected, cnaAssigner string) (versionRanges []osvschema.Range, versType string, notes []string) {
	versionTypesCount := make(map[string]int)

	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}

		versionTypesCount[vers.VersionType]++

		var introduced, fixed, lastaffected string

		// Quality check the version strings to avoid using filler content.
		vQuality := vulns.CheckQuality(vers.Version)
		if !vQuality.AtLeast(vulns.Spaces) {
			notes = append(notes, fmt.Sprintf("Version value for %s %s is filler or empty", affected.Vendor, affected.Product))
		}
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasRange := vLessThanQual.AtLeast(vulns.Spaces) || vLTOEQual.AtLeast(vulns.Spaces)
		notes = append(notes, fmt.Sprintf("Range detected: %v", hasRange))
		// Handle cases where 'lessThan' is mistakenly the same as 'version'.
		if vers.LessThan != "" && vers.LessThan == vers.Version {
			notes = append(notes, fmt.Sprintf("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version))
			hasRange = false
		}

		if hasRange {
			if vQuality.AtLeast(vulns.Spaces) {
				introduced = vers.Version
				notes = append(notes, fmt.Sprintf("%s - Introduced from version value - %s", vQuality.String(), vers.Version))
			}
			if vLessThanQual.AtLeast(vulns.Spaces) {
				fixed = vers.LessThan
				notes = append(notes, fmt.Sprintf("%s - Fixed from LessThan value - %s", vLessThanQual.String(), vers.LessThan))
			} else if vLTOEQual.AtLeast(vulns.Spaces) {
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

		if vers.VersionType == "git" {
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
		if vQuality.AtLeast(vulns.Spaces) {
			versionRanges = append(versionRanges, buildVersionRange("0", "", vers.Version))
			notes = append(notes, fmt.Sprintf("%s - Single version found %v - Assuming introduced = 0 and Fixed = %v", vQuality, vers.Version, vers.Version))
		}
	}

	// Determine the most frequent version type to return as the range type.
	maxCount := 0
	var mostFrequentVersionType string
	for versionType, count := range versionTypesCount {
		if count > maxCount {
			maxCount = count
			mostFrequentVersionType = versionType
		}
	}

	return versionRanges, mostFrequentVersionType, notes
}

// FromCVE5 creates a `vulns.Vulnerability` object from a `cves.CVE5` object.
// It populates the main fields of the OSV record, including ID, summary, details,
// references, timestamps, severity, and version information.
func FromCVE5(cve cves.CVE5, refs []cves.Reference) (*vulns.Vulnerability, []string) {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	var notes []string
	v := vulns.Vulnerability{
		Vulnerability: osvschema.Vulnerability{
			SchemaVersion:    osvschema.SchemaVersion,
			ID:               string(cve.Metadata.CVEID),
			Summary:          string(cve.Containers.CNA.Title),
			Details:          cves.EnglishDescription(cve.Containers.CNA.Descriptions),
			Aliases:          aliases,
			Related:          related,
			References:       vulns.ClassifyReferences(refs),
			DatabaseSpecific: make(map[string]interface{}),
		}}

	published, err := cves.ParseCVE5Timestamp(cve.Metadata.DatePublished)
	if err != nil {
		notes = append(notes, "Published date failed to parse, setting time to now")
		published = time.Now()
	}
	v.Vulnerability.Published = published

	modified, err := cves.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		notes = append(notes, "Modified date failed to parse, setting time to now")
		modified = time.Now()
	}
	v.Vulnerability.Modified = modified

	// Add affected version information.
	notes = append(notes, AddVersionInfo(cve, &v)...)

	// TODO(jesslowe@): Add CWEs.

	// Combine severity metrics from both CNA and ADP containers.
	var severity []cves.Metrics
	if len(cve.Containers.CNA.Metrics) != 0 {
		severity = append(severity, cve.Containers.CNA.Metrics...)
	}
	for _, adp := range cve.Containers.ADP {
		if len(adp.Metrics) != 0 {
			severity = append(severity, adp.Metrics...)
		}
	}
	if len(severity) > 0 {
		v.Severity = []osvschema.Severity{vulns.FindSeverity(severity)}
	}
	return &v, notes
}

// writeOSVToFile saves the generated OSV vulnerability record to a JSON file.
// The file is named after the vulnerability ID and placed in a subdirectory
// named after the assigning CNA.
func writeOSVToFile(id cves.CVEID, cnaAssigner string, vulnDir string, v *vulns.Vulnerability) error {
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Warnf("Failed to create dir: %v", err)
		return fmt.Errorf("failed to create dir: %w", err)
	}
	outputFile := filepath.Join(vulnDir, v.ID+extension)
	f, err := os.Create(outputFile)
	if err != nil {
		Logger.Infof("[%s] Failed to open %s for writing: %v", id, outputFile, err)
		return err
	}
	defer f.Close()

	err = v.ToJSON(f)
	if err != nil {
		Logger.Infof("Failed to write %s: %v", outputFile, err)
	} else {
		Logger.Infof("[%s]: Generated OSV record under the %s CNA", id, cnaAssigner)
	}
	return err
}

// writeMetricToFile saves the collected conversion metrics to a JSON file.
// This file provides data for analyzing the success and characteristics of the
// conversion process for a given CVE.
func writeMetricToFile(id cves.CVEID, vulnDir string) error {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics.json")
	marshalledMetrics, err := json.MarshalIndent(Metrics, "", "  ")
	if err != nil {
		Logger.Warnf("[%s]: Failed to marshal metrics: %v", id, err)
		return err
	}
	if err = os.WriteFile(metricsFile, marshalledMetrics, 0660); err != nil {
		Logger.Warnf("[%s]: Failed to write %s: %v", id, metricsFile, err)
		return err
	}
	return nil
}

// ConvertAndExportCVEToOSV is the main function for this file. It takes a CVE,
// converts it into an OSV record, collects metrics, and writes both to disk.
func ConvertAndExportCVEToOSV(cve cves.CVE5, directory string) error {
	cveId := cve.Metadata.CVEID
	cnaAssigner := cve.Metadata.AssignerShortName
	references := identifyPossibleURLs(cve)

	// Create a base OSV record from the CVE.
	v, notes := FromCVE5(cve, references)
	Metrics.Notes = append(Metrics.Notes, notes...)

	// Collect metrics about the conversion.
	extractConversionMetrics(cve, v.References)

	// Try to extract repository URLs from references.
	repos, repoNotes := cves.ReposFromReferencesCVEList(string(cveId), references, RefTagDenyList, Logger)
	Metrics.Notes = append(Metrics.Notes, repoNotes...)
	Metrics.Repos = repos

	vulnDir := filepath.Join(directory, cnaAssigner)

	// Save the OSV record to a file.
	if err := writeOSVToFile(cveId, cnaAssigner, vulnDir, v); err != nil {
		return err
	}

	// Save the conversion metrics to a file.
	if err := writeMetricToFile(cveId, vulnDir); err != nil {
		return err
	}

	return nil
}

// identifyPossibleURLs extracts and deduplicates all URLs from a CVE object.
// It searches for URLs in the CNA and ADP reference sections, as well as in
// the 'collectionUrl' and 'repo' fields of the 'affected' entries.
func identifyPossibleURLs(cve cves.CVE5) []cves.Reference {
	refs := cve.Containers.CNA.References

	for _, adp := range cve.Containers.ADP {
		if adp.References != nil {
			refs = append(refs, adp.References...)
		}
	}

	for _, affected := range cve.Containers.CNA.Affected {
		if affected.CollectionUrl != "" {
			refs = append(refs, cves.Reference{Url: affected.CollectionUrl})
		}
		if affected.Repo != "" {
			refs = append(refs, cves.Reference{Url: affected.Repo})
		}
	}

	// Deduplicate references by URL.
	slices.SortStableFunc(refs, func(a, b cves.Reference) int {
		return strings.Compare(a.Url, b.Url)
	})
	refs = slices.CompactFunc(refs, func(a, b cves.Reference) bool {
		return a.Url == b.Url
	})
	return refs
}

func main() {
	flag.Parse()

	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("cvelist-osv")
	defer logCleanup()

	// Read the input CVE JSON file.
	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		Logger.Fatalf("Failed to open file: %v", err)
	}

	var cve cves.CVE5
	if err = json.Unmarshal(data, &cve); err != nil {
		Logger.Fatalf("Failed to parse CVEList CVE JSON: %v", err)
	}

	// Perform the conversion and export the results.
	if err = ConvertAndExportCVEToOSV(cve, *outDir); err != nil {
		Logger.Warnf("[%s]: Failed to generate an OSV record: %+v", cve.Metadata.CVEID, err)
		Metrics.Outcome = "Failed"
	} else {
		Metrics.Outcome = "Successful"
	}
}
