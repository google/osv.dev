package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	outFormat = flag.String("out_format", "MinimalOSV", "Format to output {OSV,MinimalOSV}")
)
var Logger utility.LoggerWrapper
var RepoTagsCache git.RepoTagsCache
var Metrics struct {
	CNA                 string
	OSVRecordsGenerated int
	Outcome             ConversionOutcome
	RefTypesCount       map[osvschema.ReferenceType]int
	Notes               []string
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
	// len(v.References)
	refTypeCounts := make(map[osvschema.ReferenceType]int)
	for _, ref := range v.References {
		refTypeCounts[ref.Type]++
	}
	Metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		Logger.Infof("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count)
	}

	// ADP based heuristics?
	// CVE Program container seems to just add url tags for some reason
	// CISA ADP Vulnrichment often adds metrics

	// Additional information provided - CVSS, KEV, CWE etc.

}

// Takes a CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(CVE cves.CVE5, references []cves.Reference, repos []string, cache git.RepoTagsCache, directory string) error {
	// Create a base OSV record
	v, notes := vulns.FromCVE5(CVE, references)
	determineHeuristics(CVE, v)

	versions, notes := ExtractVersionInfo(CVE, repos, http.DefaultClient)

	// Attempt to resolve Version Info to commits.
	cna := CVE.Containers.CNA
	maybeVendorName := "UNKNOWN"
	maybeProductName := "UNKNOWN"
	for _, cveAff := range cna.Affected {
		if slices.Contains(VendorProductDenyList, cves.VendorProduct{Vendor: cveAff.Vendor, Product: cveAff.Product}) {
			continue
		}
		if vulns.CheckQuality(cveAff.Vendor) == vulns.Success || vulns.CheckQuality(cveAff.Vendor) == vulns.Spaces {
			maybeVendorName = cveAff.Vendor
		}
		if vulns.CheckQuality(cveAff.Product) == vulns.Success || vulns.CheckQuality(cveAff.Product) == vulns.Spaces {
			{
				maybeProductName = cveAff.Product
			}
			if maybeProductName != "UNKNOWN" && maybeVendorName != "UNKNOWN" {
				break
			}
		}
	}

	var gotUnresolvedFix, gotNoRanges bool

	if len(versions.AffectedVersions) != 0 {
		if len(repos) == 0 {
			notes = append(notes, fmt.Sprintf("[%s]: No repos to try and convert %+v to tags with", CVE.Metadata.CVEID, versions.AffectedVersions))
		} else {
			Logger.Infof("[%s]: Trying to convert version tags %+v to commits using %v", CVE.Metadata.CVEID, versions, repos)
			var err error
			versions, err = cves.GitVersionsToCommits(CVE.Metadata.CVEID, versions, repos, cache, Logger)
			if err != nil {
				notes = append(notes, fmt.Sprintf("[%s]: Failed to convert version tags to commits: %#v", CVE.Metadata.CVEID, err))
			}
			hasAnyFixedCommits := false
			for _, repo := range repos {
				if versions.HasFixedCommits(repo) {
					hasAnyFixedCommits = true
					break
				}
			}

			if versions.HasFixedVersions() && !hasAnyFixedCommits {
				notes = append(notes, fmt.Sprintf("[%s]: Failed to convert fixed version tags to commits: %#v", CVE.Metadata.CVEID, versions))
				gotUnresolvedFix = true
			}

			hasAnyLastAffectedCommits := false
			for _, repo := range repos {
				if versions.HasLastAffectedCommits(repo) {
					hasAnyLastAffectedCommits = true
					break
				}
			}

			if versions.HasLastAffectedVersions() && !hasAnyLastAffectedCommits && !hasAnyFixedCommits {
				notes = append(notes, fmt.Sprintf("[%s]: Failed to convert last_affected version tags to commits: %#v", CVE.Metadata.CVEID, versions))
				gotUnresolvedFix = true
			}
		}
	}

	slices.SortStableFunc(versions.AffectedCommits, models.AffectedCommitCompare)

	affected := osvschema.Affected{}
	vulns.AttachExtractedVersionInfo(&affected, versions)
	v.Affected = append(v.Affected, affected)

	// Save OSV record to a directory
	vulnDir := filepath.Join(directory, maybeVendorName, maybeProductName)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Warnf("Failed to create dir: %v", err)
		return fmt.Errorf("failed to create dir: %w", err)
	}

	var fileWriteErr error

	if len(v.Affected[0].Ranges) == 0 {
		notes = append(notes, fmt.Sprintf("[%s]: No affected ranges detected for %q", CVE.Metadata.CVEID, maybeProductName))
		gotNoRanges = true
	} else {
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
				Logger.Infof("[%s]: Generated OSV record for %q", CVE.Metadata.CVEID, maybeProductName)
			}
			f.Close()
		}
	}
	Metrics.Notes = notes
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
	if gotNoRanges {
		return ErrNoRanges
	}
	if gotUnresolvedFix {
		return ErrUnresolvedFix
	}

	return nil
}

func ExtractNaiveVersionInfo(cve cves.CVE5, refs []string, httpClient *http.Client) (v models.VersionInfo) {
	// gotVersions := false
	gotVersions, notes := extractVersionsFromAffected(cve.Containers.CNA, &v)
	Metrics.Notes = append(Metrics.Notes, addIDToNotes(cve.Metadata.CVEID, notes)...)

	// var extractNotes []string
	// attempt using adp as well
	for _, adp := range cve.Containers.ADP {
		notes = append(notes, "Looking at ADP")
		adpGotVersions, notes := extractVersionsFromAffected(adp, &v)
		if !gotVersions && adpGotVersions {
			gotVersions = adpGotVersions
		}
		Metrics.Notes = append(Metrics.Notes, addIDToNotes(cve.Metadata.CVEID, notes)...)
	}

	if !gotVersions {
		// If all else has failed, attempt to extract version from the description.
		v.AffectedVersions, notes = cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
		Metrics.Notes = append(Metrics.Notes, addIDToNotes(cve.Metadata.CVEID, notes)...)
		if len(v.AffectedVersions) > 0 {
			Metrics.Notes = append(Metrics.Notes, fmt.Sprintf("[%s] Extracted versions from description as no other versions found %+v", cve.Metadata.CVEID, v.AffectedVersions))
		}
	}

	if len(v.AffectedVersions) == 0 {
		Metrics.Notes = append(Metrics.Notes, "No versions detected.")
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

	return v
}

func getVendorProductNames(cna cves.CNA) (string, string) {
	maybeVendorName := "UNKNOWN"
	maybeProductName := "UNKNOWN"
	for _, cveAff := range cna.Affected {
		if slices.Contains(VendorProductDenyList, cves.VendorProduct{Vendor: cveAff.Vendor, Product: cveAff.Product}) {
			Metrics.Notes = append(Metrics.Notes, "[%s] Vendor/Product combo on VendorProductDenyList")
			continue
		}
		if vulns.CheckQuality(cveAff.Vendor) <= vulns.Spaces {
			maybeVendorName = cveAff.Vendor
		}
		if vulns.CheckQuality(cveAff.Product) <= vulns.Spaces {
			{
				maybeProductName = cveAff.Product
			}
			if maybeProductName != "UNKNOWN" && maybeVendorName != "UNKNOWN" {
				break
			}
		}
	}
	return maybeVendorName, maybeProductName
}

func CVEToMinimalOSV(CVE cves.CVE5, references []cves.Reference, repos []string, directory string) error {
	// Create a base OSV record
	v, notes := vulns.FromCVE5(CVE, references)

	// Determine CNA specific heuristics
	determineHeuristics(CVE, v)

	// versions := ExtractNaiveVersionInfo(CVE, repos, http.DefaultClient)
	// //Create naive affected packanges
	// affected := osvschema.Affected{}
	// vulns.NaivelyAttachExtractedVersionInfo(&affected, versions)
	// v.Affected = append(v.Affected, affected)
	// maybeVendorName, maybeProductName := getVendorProductNames(CVE.Containers.CNA)
	cnaAssigner := CVE.Metadata.AssignerShortName
	print(cnaAssigner)
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
			Logger.Infof("[%s]: Generated OSV record for %s under the %s CNA", CVE.Metadata.CVEID, cnaAssigner)
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

// Output a CSV summarizing per-CVE how it was handled.
func outputOutcomes(outcomes map[cves.CVEID]ConversionOutcome, reposForCVE map[cves.CVEID][]string, directory string) error {
	outcomesFile, err := os.Create(filepath.Join(directory, "outcomes.csv"))
	if err != nil {
		return err
	}
	defer outcomesFile.Close()
	w := csv.NewWriter(outcomesFile)
	w.Write([]string{"CVE", "outcome", "repos"})
	for CVE, outcome := range outcomes {
		// It's conceivable to have more than one repo for a CVE, so concatenate them.
		r := ""
		if repos, ok := reposForCVE[CVE]; ok {
			r = strings.Join(repos, " ")
		}
		w.Write([]string{string(CVE), outcome.String(), r})
	}
	w.Flush()

	if err = w.Error(); err != nil {
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
	if !slices.Contains([]string{"OSV", "MinimalOSV"}, *outFormat) {
		fmt.Fprintf(os.Stderr, "Unsupported output format: %s\n", *outFormat)
		os.Exit(1)
	}

	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("cvelist-osv")
	defer logCleanup()
	data, err := os.ReadFile(*jsonPath)
	if err != nil {
		// Metrics.Notes = append("", Metric.Notes)
		Logger.Fatalf("Failed to open file: %v", err) // double check this is best practice output
	}

	var cve cves.CVE5
	err = json.Unmarshal(data, &cve)
	if err != nil {
		Logger.Fatalf("Failed to parse CVEList CVE JSON: %v", err)
	}

	ReposForCVE := make(map[cves.CVEID][]string)
	// Metrics.Outcomes = make(map[cves.CVEID]ConversionOutcome)
	refs := identifyPossibleURLs(cve)

	CVEID := cve.Metadata.CVEID

	if len(refs) > 0 {
		repos := cves.ReposFromReferencesCVEList(string(CVEID), nil, nil, refs, RefTagDenyList, Logger)
		if len(repos) == 0 {
			Logger.Warnf("[%s]: Failed to derive any repos", CVEID)
		}
		Logger.Infof("[%s]: Derived %q for CVE", CVEID, repos)
		ReposForCVE[CVEID] = repos
	}

	Logger.Infof("[%s]: Repos: %#v", CVEID, ReposForCVE[CVEID])

	switch *outFormat {
	case "OSV":
		err = CVEToOSV(cve, refs, ReposForCVE[CVEID], RepoTagsCache, *outDir)

	case "MinimalOSV":
		err = CVEToMinimalOSV(cve, refs, ReposForCVE[CVEID], *outDir)
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

		Metrics.OSVRecordsGenerated++
		Metrics.Outcome = Successful
	}

	fmt.Printf("%+v\n", Metrics)
	// Metrics.TotalCVEs = len(parsed.Vulnerabilities)
	// err = outputOutcomes(Metrics.Outcomes, ReposForCVE, *outDir)
	// if err != nil {
	// 	// Log entry with size 1.15M exceeds maximum size of 256.0K
	// 	fmt.Fprintf(os.Stderr, "Failed to write out metrics: %v", err)
	// }
	// // Outcomes is too big to log, so zero it out.
	// Metrics.Outcomes = nil
	// Logger.Infof("%s Metrics: %+v", filepath.Base(*jsonPath), Metrics)
}
