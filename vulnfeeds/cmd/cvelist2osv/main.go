package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ConversionOutcome int

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

func (c ConversionOutcome) String() string {
	return [...]string{
		"ConversionUnknown",
		"Successful",
		"Rejected",
		"NoSoftware",
		"NoRepos",
		"NoRanges",
		"FixUnresolvable"}[c]
}

const (
	extension = ".json"
)

const (
	// Set of enums for categorizing conversion outcomes.
	ConversionUnknown ConversionOutcome = iota // Shouldn't happen
	Successful                                 // It worked!
	Rejected                                   // The CVE was rejected
	NoSoftware                                 // The CVE had no CPEs relating to software (i.e. Operating Systems or Hardware).
	NoRepos                                    // The CPE Vendor/Product had no repositories derived for it.
	NoRanges                                   // No viable commit ranges could be calculated from the repository for the CVE's CPE(s).
	FixUnresolvable                            // Partial resolution of versions, resulting in a false positive.
)

var (
	jsonPath  = flag.String("cve_json", "", "Path to CVEList JSON to examine.")
	outDir    = flag.String("out_dir", "", "Path to output results.")
	outFormat = flag.String("out_format", "OSV", "Format to output {OSV}")
)
var Logger utility.LoggerWrapper
var RepoTagsCache git.RepoTagsCache
var Metrics struct {
	CNA           string
	Outcome       ConversionOutcome
	RefTypesCount map[osvschema.ReferenceType]int
	Notes         []string
}

// RefTagDenyList: References with these tags have been found to contain completely unrelated
// repositories and can be misleading as to the software's true repository,
// Currently not used for this purpose due to undesired false positives
// reducing the number of valid records successfully converted.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these though.
}

// VendorProducts known not to be Open Source software and causing
// cross-contamination of repo derivation between CVEs.
var VendorProductDenyList = []cves.VendorProduct{
	// Three strikes and the entire netapp vendor is out...
	{Vendor: "netapp", Product: ""},
	// [CVE-2021-28957]: Incorrectly associates with github.com/lxml/lxml
	{Vendor: "oracle", Product: "zfs_storage_appliance_kit"},
	{Vendor: "gradle", Product: "enterprise"}, // The OSS repo gets mis-attributed via CVE-2020-15767
}

// extractVersionsFromAffected extracts affected versions from the CNA container of a CVE.
// It populates the models.AffectedVersion slice based on the versioning information
// provided in the CVE data, handling both explicit ranges (lessThan, lessThanOrEqual)
// and single affected versions. It also attempts to extract versions from text
// descriptions if direct version ranges are not available.
//
// Parameters:
//   - cna: The CNA container from the CVE5 object.
//   - versionInfo: The models.VersionInfo struct to populate with affected versions.
//
// Returns:
//   - bool: True if any versions were successfully extracted, false otherwise.
//   - []string: A slice of notes or warnings generated during the extraction process.
func extractVersionsFromAffected(cna cves.CNA, versionInfo *models.VersionInfo) (bool, []string) {
	gotVersions := false
	var notes []string
	for _, cveAff := range cna.Affected {
		for _, v := range cveAff.Versions {
			if v.Status != "affected" {
				continue
			}

			var introduced, fixed, lastaffected string

			// Quality check
			vQuality := vulns.CheckQuality(v.Version)
			if vQuality == vulns.Filler {
				notes = append(notes, fmt.Sprintf("Version value for %s %s is filler or empty", cveAff.Vendor, cveAff.Product))
			}
			vLessThanQual := vulns.CheckQuality(v.LessThan)
			vLTOEQual := vulns.CheckQuality(v.LessThanOrEqual)

			hasRange := vLessThanQual <= vulns.Spaces || vLTOEQual <= vulns.Spaces
			if v.LessThan != "" && v.LessThan == v.Version {
				notes = append(notes, fmt.Sprintf("Warning: lessThan (%s) is the same as introduced (%s)\n", v.LessThan, v.Version))
				// Only this specific version affected or up to this version
				hasRange = false
			}
			if hasRange {
				if vQuality <= vulns.Spaces {
					introduced = v.Version
					notes = append(notes, fmt.Sprintf("%s - Introduced from version value", vQuality.String()))
				}
				if vLessThanQual <= vulns.Spaces {
					fixed = v.LessThan
					notes = append(notes, fmt.Sprintf("%s - Fixed from LessThan value", vLessThanQual.String()))
				} else if vLTOEQual <= vulns.Spaces {
					lastaffected = v.LessThanOrEqual
					notes = append(notes, fmt.Sprintf("%s - LastAffected from LessThanOrEqual value", vLTOEQual.String()))
				}
			} else {
				// In this case only v.Version exists which either means that it is _only_ that version that is
				// affected, but more likely, it affects up to that version. It could also mean that the range is given
				// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.
				notes = append(notes, "Only version exists")
				possibleVersions, note := cves.ExtractVersionsFromText(nil, v.Version)
				if note != nil {
					notes = append(notes, note...)
				}
				if possibleVersions != nil {
					versionInfo.AffectedVersions = append(versionInfo.AffectedVersions, possibleVersions...)
					notes = append(notes, fmt.Sprintf("Versions retrieved from text"))
					gotVersions = true
					continue
				}

				// We might only have a single version. Assume it affects up to that version
				if vQuality <= vulns.Spaces {
					introduced = "0"
					lastaffected = v.Version
					notes = append(notes, fmt.Sprintf("%s - Single version found. Assuming introduced is 0, and LastAffected is given version", vQuality))
				}

			}
			if introduced == "" && fixed == "" && lastaffected == "" {
				continue
			}
			gotVersions = true
			possibleNewAffectedVersion := models.AffectedVersion{
				Introduced:   introduced,
				Fixed:        fixed,
				LastAffected: lastaffected,
			}
			notes = append(notes, fmt.Sprintf("Possible new affected versions i:%s l:%s f:%s", possibleNewAffectedVersion.Introduced, possibleNewAffectedVersion.LastAffected, possibleNewAffectedVersion.Fixed))

			if slices.Contains(versionInfo.AffectedVersions, possibleNewAffectedVersion) {
				// Avoid appending duplicates
				continue
			}
			versionInfo.AffectedVersions = append(versionInfo.AffectedVersions, possibleNewAffectedVersion)
		}
	}
	return gotVersions, notes
}

func addIDToNotes(id cves.CVEID, notes []string) []string {
	var updatedNotes []string
	for _, note := range notes {
		updatedNotes = append(updatedNotes, fmt.Sprintf("[%s] %s", id, note))
	}
	return updatedNotes
}

func ExtractVersionInfo(cve cves.CVE5, refs []string, httpClient *http.Client) (v models.VersionInfo, notes []string) {
	for _, reference := range refs {
		// (Potentially faulty) Assumption: All viable Git commit reference links are fix commits.
		if commit, err := cves.ExtractGitCommit(reference, models.Fixed, httpClient); err == nil {
			v.AffectedCommits = append(v.AffectedCommits, commit)
		}
	}
	gotVersions := false
	gotVersions, notes = extractVersionsFromAffected(cve.Containers.CNA, &v)

	// attempt using adp as well
	for _, adp := range cve.Containers.ADP {
		notes = append(notes, "Looking at ADP")
		adpGotVersions, extractNotes := extractVersionsFromAffected(adp, &v)
		if !gotVersions && adpGotVersions {
			gotVersions = adpGotVersions
		}
		notes = append(notes, extractNotes...)
	}

	if !gotVersions {
		var extractNotes []string
		// If all else has failed, attempt to extract version from the description.
		v.AffectedVersions, extractNotes = cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
		notes = append(notes, extractNotes...)
		if len(v.AffectedVersions) > 0 {
			log.Printf("[%s] Extracted versions from description = %+v", cve.Metadata.CVEID, v.AffectedVersions)
		}
	}

	if len(v.AffectedVersions) == 0 {
		notes = append(notes, "No versions detected.")
	}

	// Remove any lastaffected versions in favour of fixed versions.
	if v.HasFixedVersions() {
		affectedVersionsWithoutLastAffected := []models.AffectedVersion{}
		for _, av := range v.AffectedVersions {
			if av.LastAffected != "" {
				continue
			}
			affectedVersionsWithoutLastAffected = append(affectedVersionsWithoutLastAffected, av)
		}
		v.AffectedVersions = affectedVersionsWithoutLastAffected
	}

	return v, notes
}

func determineHeuristics(cve cves.CVE5, v *vulns.Vulnerability) {
	// CNA based heuristics
	Metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis
	// Reference based heuristics
	// Count number of references of each type
	refTypeCounts := make(map[osvschema.ReferenceType]int)
	for _, ref := range v.References {
		refTypeCounts[ref.Type]++
	}
	Metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		Metrics.Notes = append(Metrics.Notes, fmt.Sprintf("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count))
	}

	// ADP based heuristics?
	// CVE Program container seems to just add url tags for some reason
	// CISA ADP Vulnrichment often adds metrics

	// Additional information provided - CVSS, KEV, CWE etc.

}

func AddVersionInfo(cve cves.CVE5, v *vulns.Vulnerability) []string {
	var notes []string
	if cve.Metadata.AssignerShortName == "Linux" {
		pkg := osvschema.Package{
			Ecosystem: string(osvschema.EcosystemLinux),
			Name:      "Kernel"}

		cpeRanges, err := getCPERanges(cve)
		if err != nil {
			notes = append(notes, err.Error())
		}
		if cpeRanges != nil {
			nA := osvschema.Affected{
				Package: pkg,
			}
			for _, r := range cpeRanges {
				r.Type = osvschema.RangeEcosystem
				nA.Ranges = append(nA.Ranges, r)
			}
			v.Affected = append(v.Affected, nA)
		}
	}

	cna := cve.Containers.CNA
	adps := cve.Containers.ADP
	gotVersions := false

	affected := cna.Affected
	for _, adp := range adps {
		if adp.Affected != nil {
			affected = append(affected, adp.Affected...)
		}
	}

	// Attempt to extract from Affected field
	for _, cveAff := range affected {
		versionRanges, versionType, extractNotes := ExtractFromAffected(cveAff, cve.Metadata.AssignerShortName)
		if len(versionRanges) == 0 {
			notes = append(notes, extractNotes...)
			continue
		} else {
			gotVersions = true
		}
		if versionType == "git" {
			nA := osvschema.Affected{}
			for _, vr := range versionRanges {
				vr.Type = osvschema.RangeGit
				vr.Repo = cveAff.Repo
				nA.Ranges = append(nA.Ranges, vr)
			}

			v.Affected = append(v.Affected, nA)
		} else {
			nA := osvschema.Affected{}
			for _, vr := range versionRanges {
				vr.Type = osvschema.RangeEcosystem
				nA.Ranges = append(nA.Ranges, vr)
			}
			v.Affected = append(v.Affected, nA)
		}
	}

	// No versions were extracted from Affected so attempt to extract from CPE field
	if !gotVersions {
		notes = append(notes, "No versions in affected, attempting to extract from CPE")
		cpeRanges, err := getCPERanges(cve)
		if err != nil {
			notes = append(notes, err.Error())
		}
		if len(cpeRanges) != 0 {
			nA := osvschema.Affected{}
			for _, vr := range cpeRanges {
				vr.Type = osvschema.RangeEcosystem
				nA.Ranges = append(nA.Ranges, vr)
			}
			v.Affected = append(v.Affected, nA)
		}
	}

	// CPEs was a bust so try to extract from the description
	if !gotVersions {
		notes = append(notes, "No versions in CPEs so attempting extraction from description")
		versions, extractNotes := cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
		notes = append(notes, extractNotes...)
		if len(versions) > 0 {
			// NOT SAVED CURRENTLY - need to add better validation before I'm comfortable saving these
			notes = append(notes, fmt.Sprintf("Extracted versions from description as no other versions found %+v", versions))
		}
	}

	return notes
}

func addToVersionRange(versionRange *osvschema.Range, intro string, lastAff string, fixed string) {
	if intro != "" {
		versionRange.Events = append(versionRange.Events, osvschema.Event{
			Introduced: intro})
	}
	if fixed != "" {
		versionRange.Events = append(versionRange.Events, osvschema.Event{
			Fixed: fixed})
	} else if lastAff != "" {
		versionRange.Events = append(versionRange.Events, osvschema.Event{
			LastAffected: lastAff,
		})
	}

}

func getCPERanges(cve cves.CVE5) (versionRanges []osvschema.Range, err error) {
	for _, c := range cve.Containers.CNA.CPEApplicability {
		for _, node := range c.Nodes {
			if node.Operator != "OR" {
				continue
			}
			for _, match := range node.CPEMatch {
				if match.Vulnerable != true {
					continue
				}
				versionRange := osvschema.Range{}
				if match.VersionEndExcluding != "" {
					addToVersionRange(&versionRange, match.VersionStartIncluding, "", match.VersionEndExcluding)
				} else if match.VersionEndIncluding != "" {
					addToVersionRange(&versionRange, match.VersionStartIncluding, match.VersionEndIncluding, "")
				}
				if len(versionRange.Events) != 0 {
					versionRanges = append(versionRanges, versionRange)
				}
			}
		}
	}
	if len(versionRanges) == 0 {
		return nil, fmt.Errorf("No Versions Extracted")
	}
	return versionRanges, nil
}

func ExtractFromAffected(affected cves.Affected, cnaAssigner string) (versionRanges []osvschema.Range, rangeType string, notes []string) {

	if affected.DefaultStatus == "affected" {

		if cnaAssigner == "Linux" {
			notes = append(notes, "Skipping Linux Affected range versions in favour of CPE versions")
			return nil, "", notes
		}
		// Find the inverse affected ranges
		// ranges, notes = findInverseAffectedRanges(affected)

		// Deal with this later
		// if len(versionRange.Events) != 0 {
		// 	return versionRange, string(osvschema.RangeSemVer), notes
		// }
		// TODO(jesslowe): add more notes here
		return nil, "", notes
	}

	versionTypesCount := make(map[string]int)

	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}
		_, ok := versionTypesCount[vers.VersionType]
		if ok {
			versionTypesCount[vers.VersionType]++
		} else {
			versionTypesCount[vers.VersionType] = 0
		}

		var introduced, fixed, lastaffected string

		// Quality check
		vQuality := vulns.CheckQuality(vers.Version)
		if vQuality >= vulns.Filler {
			notes = append(notes, fmt.Sprintf("Version value for %s %s is filler or empty", affected.Vendor, affected.Product))
		}
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasRange := vLessThanQual <= vulns.Spaces || vLTOEQual <= vulns.Spaces
		notes = append(notes, fmt.Sprintf("Range detected: %v", hasRange))
		if vers.LessThan != "" && vers.LessThan == vers.Version {
			notes = append(notes, fmt.Sprintf("Warning: lessThan (%s) is the same as introduced (%s)\n", vers.LessThan, vers.Version))
			// Only this specific version affected or up to this version
			hasRange = false
		}
		if hasRange {
			if vQuality <= vulns.Spaces {
				introduced = vers.Version
				notes = append(notes, fmt.Sprintf("%s - Introduced from version value - %s", vQuality.String(), vers.Version))
			}
			if vLessThanQual <= vulns.Spaces {
				fixed = vers.LessThan
				notes = append(notes, fmt.Sprintf("%s - Fixed from LessThan value - s %s", vLessThanQual.String(), vers.LessThan))
			} else if vLTOEQual <= vulns.Spaces {
				lastaffected = vers.LessThanOrEqual
				notes = append(notes, fmt.Sprintf("%s - LastAffected from LessThanOrEqual value- %s", vLTOEQual.String(), vers.LessThanOrEqual))
			}

			if introduced != "" && fixed != "" {
				versionRange := osvschema.Range{}
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Introduced: introduced})
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Fixed: fixed,
				})
				versionRanges = append(versionRanges, versionRange)
				notes = append(notes, "vers range updated fixed")
			} else if introduced != "" && lastaffected != "" {
				versionRange := osvschema.Range{}
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Introduced: introduced})
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					LastAffected: lastaffected,
				})
				versionRanges = append(versionRanges, versionRange)
				notes = append(notes, "vers range updated la")
			}

		} else {
			// In this case only vers.Version exists which either means that it is _only_ that version that is
			// affected, but more likely, it affects up to that version. It could also mean that the range is given
			// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.
			notes = append(notes, "Only version exists")
			if cnaAssigner == "GitHub_M" {
				av, err := git.ParseVersionRange(vers.Version)
				if err == nil {
					if av.Introduced != "" && av.Fixed != "" {
						versionRange := osvschema.Range{}
						addToVersionRange(&versionRange, av.Introduced, "", av.Fixed)
						versionRanges = append(versionRanges, versionRange)
					} else if av.Introduced != "" && av.LastAffected != "" {
						versionRange := osvschema.Range{}
						addToVersionRange(&versionRange, av.Introduced, av.LastAffected, "")
						versionRanges = append(versionRanges, versionRange)
						notes = append(notes, "vers range updated la")
					}
				}
				continue
			}

			if vers.VersionType == "git" {
				versionRange := osvschema.Range{}
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Introduced: vers.Version,
				})
				versionRanges = append(versionRanges, versionRange)
				continue
			}

			possibleVersions, note := cves.ExtractVersionsFromText(nil, vers.Version)
			if note != nil {
				notes = append(notes, note...)
			}
			if possibleVersions != nil {
				// versionInfo.AffectedVersions = append(versionInfo.AffectedVersions, possibleVersions...)
				notes = append(notes, fmt.Sprintf("Versions retrieved from text but not used CURRENTLY"))
				continue
			}

			// We might only have a single version. Assume it affects up to that version
			if vQuality <= vulns.Spaces {
				versionRange := osvschema.Range{}
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Introduced: "0"})
				versionRange.Events = append(versionRange.Events, osvschema.Event{
					Fixed: vers.Version,
				})
				versionRanges = append(versionRanges, versionRange)
				notes = append(notes, fmt.Sprintf("%s - Single version found %v - Assuming introduced = 0 and Fixed = %v", vQuality, vers.Version, vers.Version))
			}

		}
		if introduced == "" && fixed == "" && lastaffected == "" {
			continue
		}

	}
	// find the versionsType with the highest count
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

func findInverseAffectedRanges(cveAff cves.Affected) (ranges []osvschema.Range, notes []string) {
	var introduced []string
	var fixed []string
	seenIntroduced := map[string]bool{}
	seenFixed := map[string]bool{}
	for _, vers := range cveAff.Versions {
		// Read them each individually
		if vers.Status == "affected" {
			introduced = append(introduced, vers.Version)
		}
		if vers.Status == "unaffected" {
			if vers.Version == "0" {
				continue
			}
			fixed = append(fixed, vers.Version)
			// double check that the next one contains a *
			minorVers := strings.SplitAfter(vers.LessThanOrEqual, ".*")[0]

			nextMinorVers := strings.Split(minorVers, ".")

			intMin, err := strconv.Atoi(nextMinorVers[len(nextMinorVers)-1])

			if err == nil {
				nex := fmt.Sprintf("%s.%b", minorVers, intMin+1)
				introduced = append(introduced, nex)
			}
		}
	}
	if len(introduced) < 1 {
		introduced = append(introduced, "0")
	}

	for _, intro := range introduced {
		if _, seen := seenIntroduced[intro]; !seen {
			versionRange := osvschema.Range{}
			versionRange.Events = append(versionRange.Events, osvschema.Event{
				Introduced: intro,
			})
			ranges = append(ranges, versionRange)

			seenIntroduced[intro] = true
			notes = append(notes, fmt.Sprintf("Introduced from version value - %s", intro))
		}
	}
	for _, fix := range fixed {
		if _, seen := seenFixed[fix]; fix != "" && !seen {
			versionRange := osvschema.Range{}
			versionRange.Events = append(versionRange.Events, osvschema.Event{
				Fixed: fix,
			})
			seenFixed[fix] = true
			ranges = append(ranges, versionRange)
			notes = append(notes, fmt.Sprintf("Fixed from version value - %s", fix))
		}
	}
	return ranges, notes
}

func FromCVE5(cve cves.CVE5, refs []cves.Reference) (*vulns.Vulnerability, []string) {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	var err error
	var notes []string
	v := vulns.Vulnerability{}
	v.SchemaVersion = osvschema.SchemaVersion
	v.ID = string(cve.Metadata.CVEID)
	v.Summary = string(cve.Containers.CNA.Title)
	v.Details = cves.EnglishDescription(cve.Containers.CNA.Descriptions)
	v.Aliases = aliases
	v.Related = related
	v.Published, err = cves.ParseCVE5Timestamp(cve.Metadata.DatePublished)
	if err != nil {
		notes = append(notes, "Published date failed to parse")
	}
	v.Modified, err = cves.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		notes = append(notes, "Modified date failed to parse")
	}
	v.References = vulns.ClassifyReferences(refs)
	// Add affected version
	notes = append(notes, AddVersionInfo(cve, &v)...)
	v.DatabaseSpecific = make(map[string]interface{})
	CPEs := vulns.GetCPEs(cve.Containers.CNA.CPEApplicability)
	if len(CPEs) != 0 {
		v.DatabaseSpecific["CPE"] = vulns.Unique(CPEs)
	}

	// TODO: add CWEs

	// Find metrics across CNA and adp
	var metrics []cves.Metrics
	if len(cve.Containers.CNA.Metrics) != 0 {
		metrics = append(metrics, cve.Containers.CNA.Metrics...)
	}
	for _, adp := range cve.Containers.ADP {
		if len(adp.Metrics) != 0 {
			metrics = append(metrics, adp.Metrics...)
		}
	}
	for _, m := range metrics {
		v.AddSeverity(m)
	}
	return &v, notes
}

func CVEToOSV(CVE cves.CVE5, references []cves.Reference, repos []string, directory string) error {
	// Create a base OSV record
	v, notes := FromCVE5(CVE, references)

	// Determine CNA specific heuristics
	determineHeuristics(CVE, v)
	cnaAssigner := CVE.Metadata.AssignerShortName

	// Save OSV record to a directory
	vulnDir := filepath.Join(directory, cnaAssigner)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Warnf("Failed to create dir: %v", err)
		return fmt.Errorf("failed to create dir: %w", err)
	}

	var fileWriteErr error

	// Only write out the OSV file if we have ranges.
	outputFile := filepath.Join(vulnDir, v.ID+extension)

	f, err := os.Create(outputFile)
	if err != nil {
		notes = append(notes, fmt.Sprintf("Failed to open %s for writing: %v", outputFile, err))
		fileWriteErr = err
	} else {
		err = v.ToJSON(f)
		if err != nil {
			notes = append(notes, fmt.Sprintf("Failed to write %s: %v", outputFile, err))
			fileWriteErr = err
		} else {
			Logger.Infof("[%s]: Generated OSV record under the %s CNA", CVE.Metadata.CVEID, cnaAssigner)
		}
		f.Close()
	}

	Metrics.Notes = append(Metrics.Notes, notes...)
	metricsFile := filepath.Join(vulnDir, v.ID+".metrics.json")
	if marshalledMetrics, err := json.MarshalIndent(Metrics, "", "  "); err != nil {
		Logger.Warnf("[%s]: Failed to marshal metrics: %v", CVE.Metadata.CVEID, err)
	} else {
		if err = os.WriteFile(metricsFile, marshalledMetrics, 0660); err != nil {
			Logger.Warnf("[%s]: Failed to write %s: %v", CVE.Metadata.CVEID, metricsFile, err)
		}
	}

	if fileWriteErr != nil {
		return fileWriteErr
	}

	return nil
}

// identifyPossibleURLs extracts all possible URLs from a CVE5 object,
// including those in CNA and ADP containers, and affected package information.
// It deduplicates the URLs before returning them.
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

	// Remove duplicate URLs
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
	if !slices.Contains([]string{"OSV"}, *outFormat) {
		fmt.Fprintf(os.Stderr, "Unsupported output format: %s\n", *outFormat)
		os.Exit(1)
	}

	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("cvelist-osv")
	defer logCleanup()
	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		Logger.Fatalf("Failed to open file: %v", err) // double check this is best practice output
	}

	var cve cves.CVE5
	err = json.Unmarshal(data, &cve)
	if err != nil {
		Logger.Fatalf("Failed to parse CVEList CVE JSON: %v", err)
	}

	ReposForCVE := make(map[cves.CVEID][]string)
	refs := identifyPossibleURLs(cve)

	CVEID := cve.Metadata.CVEID

	if len(refs) > 0 {
		repos, notes := cves.ReposFromReferencesCVEList(string(CVEID), nil, nil, refs, RefTagDenyList, Logger)
		addIDToNotes(CVEID, notes)
		if len(repos) == 0 {
			Logger.Warnf("[%s]: Failed to derive any repos", CVEID)
		}
		Metrics.Notes = append(Metrics.Notes, fmt.Sprintf("[%s]: Derived %q for CVE", CVEID, repos))
		ReposForCVE[CVEID] = repos
	}

	Metrics.Notes = append(Metrics.Notes, fmt.Sprintf("[%s]: Repos: %#v", CVEID, ReposForCVE[CVEID]))

	switch *outFormat {
	case "OSV":
		err = CVEToOSV(cve, refs, ReposForCVE[CVEID], *outDir)
	}
	// Parse this error to determine which failure mode it was
	if err != nil {
		Logger.Warnf("[%s]: Failed to generate an OSV record: %+v", CVEID, err)
		if errors.Is(err, ErrNoRanges) {
			Metrics.Outcome = NoRanges
		} else if errors.Is(err, ErrUnresolvedFix) {
			Metrics.Outcome = FixUnresolvable
		} else {
			Metrics.Outcome = ConversionUnknown
		}
	} else {
		Metrics.Outcome = Successful
	}
}
