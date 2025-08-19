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
var Metrics struct {
	CNA           string
	Outcome       string
	Repos         []string
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

// extractConversionMetrics examines a CVE and extracts metrics and heuristics about it.
func extractConversionMetrics(cve cves.CVE5, refs []osvschema.Reference) {
	// CNA based heuristics
	Metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis
	// Reference based heuristics
	// Count number of references of each type
	refTypeCounts := make(map[osvschema.ReferenceType]int)
	for _, ref := range refs {
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

// AddVersionInfo attempts to extract versions into version ranges and events
// through different methods, sometimes based on specific CNA behaviour.
func AddVersionInfo(cve cves.CVE5, v *vulns.Vulnerability) []string {
	var notes []string
	if cve.Metadata.AssignerShortName == "Linux" {
		pkg := osvschema.Package{
			Ecosystem: string(osvschema.EcosystemLinux),
			Name:      "Kernel"}

		cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
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
			nA.DatabaseSpecific = make(map[string]interface{})
			nA.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
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

	// Attempt to extract version ranges from Affected field
	for _, cveAff := range affected {
		versionRanges, versionType, extractNotes := ExtractVersionsFromAffectedField(cveAff, cve.Metadata.AssignerShortName)
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
			if cve.Metadata.AssignerShortName == "Linux" {
				nA.Package = osvschema.Package{
					Ecosystem: string(osvschema.EcosystemLinux),
					Name:      "Kernel"}
			}
			v.Affected = append(v.Affected, nA)
		}
	}

	// No versions were extracted from Affected so attempt to extract from CPE field
	if !gotVersions {
		notes = append(notes, "No versions in affected, attempting to extract from CPE")
		cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
		if err != nil {
			notes = append(notes, err.Error())
		}
		if len(cpeRanges) != 0 {
			nA := osvschema.Affected{}
			for _, vr := range cpeRanges {
				vr.Type = osvschema.RangeEcosystem
				nA.Ranges = append(nA.Ranges, vr)
			}
			nA.DatabaseSpecific = make(map[string]interface{})
			nA.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
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

// addToVersionRange is a helper function that will take a range and versions and add them as events
func addToVersionRange(versionRange *osvschema.Range, intro string, lastAff string, fixed string) {
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
}

// findCPEVersionRanges gets the version ranges from provided CPE ranges
func findCPEVersionRanges(cve cves.CVE5) (versionRanges []osvschema.Range, cpes []string, err error) {

	// TODO(jesslowe): add logic to also extract cpes from affected field (CVE-2025-1110)
	for _, c := range cve.Containers.CNA.CPEApplicability {
		for _, node := range c.Nodes {
			if node.Operator != "OR" {
				continue
			}
			for _, match := range node.CPEMatch {
				if match.Vulnerable != true {
					continue
				}
				cpes = append(cpes, match.Criteria)
				versionRange := osvschema.Range{}

				if match.VersionStartIncluding == "" {
					match.VersionStartIncluding = "0"
					// no starting version was given so assuming introduced was 0.
				}

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
		return nil, nil, fmt.Errorf("No Versions Extracted")
	}
	return versionRanges, cpes, nil
}

// ExtractVersionsFromAffected extracts affected versions from the affected field  in the CNA container of a CVE.
// It populates the models.AffectedVersion slice based on the versioning information
// provided in the CVE data, handling both explicit ranges (lessThan, lessThanOrEqual)
// and single affected versions. It also attempts to extract versions from text
// descriptions if direct version ranges are not available.
//
// Parameters:
//   - affected: The CNA container from the CVE5 object.
//   - cnaAssigner: The CNA responsible for the CVE
//
// Returns:
//   - versionRanges
//   - rangeType
//   - notes

func ExtractVersionsFromAffectedField(affected cves.Affected, cnaAssigner string) (versionRanges []osvschema.Range, rangeType string, notes []string) {

	if affected.DefaultStatus == "affected" {
		if cnaAssigner == "Linux" {

			notes = append(notes, "Skipping Linux Affected range versions in favour of CPE versions")
			return nil, "", notes
		}
		// Find the inverse affected ranges
		ranges, notes := findInverseAffectedRanges(affected)

		// Deal with this later
		if len(ranges) != 0 {
			return ranges, string(osvschema.RangeSemVer), notes
		}
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

func sortBadSemver(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	majorA, errA := strconv.Atoi(partsA[0])
	majorB, errB := strconv.Atoi(partsB[0])

	_ = errA
	_ = errB
	if c := cmp.Compare(majorA, majorB); c != 0 {
		return c
	}

	minorA, errA := strconv.Atoi(partsA[1])
	minorB, errB := strconv.Atoi(partsB[1])
	if c := cmp.Compare(minorA, minorB); c != 0 {
		return c
	}
	patchA, errA := strconv.Atoi(partsA[2])
	patchB, errB := strconv.Atoi(partsB[2])
	return cmp.Compare(patchA, patchB)
}

// findInverseAffectedRanges takes the given 'unaffected' ranges and attempts to determine the affected version ranges
func findInverseAffectedRanges(cveAff cves.Affected) (ranges []osvschema.Range, notes []string) {
	var introduced []string
	var fixed []string
	for _, vers := range cveAff.Versions {
		// Read them each individually
		if vers.Status == "affected" {
			introduced = append(introduced, fmt.Sprintf("%s.0", vers.Version))
		}
		if vers.Status == "unaffected" {
			if vers.Version == "0" {
				continue
			}
			if vers.VersionType != "semver" {
				continue
			}
			fixed = append(fixed, vers.Version)
			// Find the next minor version up
			minorVers := strings.Split(vers.LessThanOrEqual, ".*")[0]
			parts := strings.Split(minorVers, ".")
			intMin, err := strconv.Atoi(parts[len(parts)-1])

			if err == nil {
				nex := fmt.Sprintf("%s.%d.0", parts[0], intMin+1)
				introduced = append(introduced, nex)
			}
		}
	}

	slices.SortFunc(introduced, sortBadSemver)
	slices.SortFunc(fixed, sortBadSemver)
	if fixed[0] < introduced[0] {
		introduced = append([]string{"0"}, introduced...)
	}

	for index, f := range fixed {
		versionRange := osvschema.Range{}
		addToVersionRange(&versionRange, introduced[index], "", f)
		notes = append(notes, fmt.Sprintf("Introduced from version value - %s", introduced[index]))
		notes = append(notes, fmt.Sprintf("Fixed from version value - %s", f))
		ranges = append(ranges, versionRange)
	}

	return ranges, notes
}

// FromCVE5 creates a Vulnerability from a CVE5 object.
func FromCVE5(cve cves.CVE5, refs []cves.Reference) (*vulns.Vulnerability, []string) {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	var err error
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

	// Add affected versions
	notes = append(notes, AddVersionInfo(cve, &v)...)

	// TODO(jesslowe@): add CWEs

	// Find severity metrics across CNA and adp
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
	} else {
		err = v.ToJSON(f)
		if err != nil {
			Logger.Infof("Failed to write %s: %v", outputFile, err)

		} else {
			Logger.Infof("[%s]: Generated OSV record under the %s CNA", id, cnaAssigner)
		}
		f.Close()
	}
	return err
}

func writeMetricToFile(id cves.CVEID, vulnDir string) error {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics.json")
	if marshalledMetrics, err := json.MarshalIndent(Metrics, "", "  "); err != nil {
		Logger.Warnf("[%s]: Failed to marshal metrics: %v", id, err)
		return err
	} else {
		if err = os.WriteFile(metricsFile, marshalledMetrics, 0660); err != nil {
			Logger.Warnf("[%s]: Failed to write %s: %v", id, metricsFile, err)
			return err
		}
	}
	return nil
}

// ConvertAndExportCVEToOSV converts a CVE into an OSV finding and writes it to a file.
func ConvertAndExportCVEToOSV(CVE cves.CVE5, directory string) error {
	cveId := CVE.Metadata.CVEID
	cnaAssigner := CVE.Metadata.AssignerShortName
	references := identifyPossibleURLs(CVE)

	// Create a base OSV record
	v, notes := FromCVE5(CVE, references)
	Metrics.Notes = append(Metrics.Notes, notes...)

	// Determine CNA specific heuristics and conversion metrics
	extractConversionMetrics(CVE, v.References)

	// Try to extract some repositories
	repos, notes := cves.ReposFromReferencesCVEList(string(cveId), references, RefTagDenyList, Logger)
	Metrics.Notes = append(Metrics.Notes, notes...)
	Metrics.Repos = repos

	vulnDir := filepath.Join(directory, cnaAssigner)

	// Save OSV record to a directory
	err := writeOSVToFile(cveId, cnaAssigner, vulnDir, v)
	if err != nil {
		return err
	}

	// Save conversion metrics to disk
	err = writeMetricToFile(cveId, vulnDir)
	if err != nil {
		return err
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

	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("cvelist-osv")
	defer logCleanup()
	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		Logger.Fatalf("Failed to open file: %v", err)
	}

	var cve cves.CVE5
	err = json.Unmarshal(data, &cve)
	if err != nil {
		Logger.Fatalf("Failed to parse CVEList CVE JSON: %v", err)
	}

	err = ConvertAndExportCVEToOSV(cve, *outDir)

	if err != nil {
		Logger.Warnf("[%s]: Failed to generate an OSV record: %+v", cve.Metadata.CVEID, err)
		Metrics.Outcome = "Failed"
	} else {
		Metrics.Outcome = "Successful"
	}
}
