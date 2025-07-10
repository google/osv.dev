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
	outFormat = flag.String("out_format", "OSV", "Format to output {OSV,PackageInfo}")
)
var Logger utility.LoggerWrapper
var RepoTagsCache git.RepoTagsCache
var Metrics struct {
	TotalCVEs           int
	CVEsForApplications int
	CVEsForKnownRepos   int
	OSVRecordsGenerated int
	Outcomes            map[cves.CVEID]ConversionOutcome // Per-CVE-ID record of conversion result.
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
	var notes []string
	gotVersions := false
	for _, cveAff := range cna.Affected {
		for _, v := range cveAff.Versions {
			if v.Status != "affected" {
				continue
			}
			var introduced, fixed, lastaffected string
			hasRange := vulns.IsNotEmptyOrFiller(v.LessThan) || vulns.IsNotEmptyOrFiller(v.LessThanOrEqual)
			if v.LessThan != "" && v.LessThan == v.Version {
				fmt.Printf("Warning: lessThan (%s) is the same as introduced (%s)\n", v.LessThan, v.Version)
				// Only this specific version affected or up to this version
				hasRange = false
			}

			if hasRange {
				if vulns.IsNotEmptyOrFiller(v.Version) {
					introduced = v.Version
				}
				if vulns.IsNotEmptyOrFiller(v.LessThan) {
					fixed = v.LessThan
				} else if vulns.IsNotEmptyOrFiller(v.LessThanOrEqual) {
					lastaffected = v.LessThanOrEqual
				}
			} else {
				// In this case only v.Version exists which either means that it is _only_ that version that is
				// affected, but more likely, it affects up to that version. It could also mean that the range is given
				// in one line instead - like "< 1.5.3" or "< 2.45.4, >= 2.0 " or just "before 1.4.7", so check for that.

				possibleVersions, note := cves.ExtractVersionsFromText(nil, v.Version)
				if note != nil {
					notes = append(notes, note...)
				}
				if possibleVersions != nil {
					versionInfo.AffectedVersions = append(versionInfo.AffectedVersions, possibleVersions...)
					gotVersions = true
					continue
				}

				// We might only have a single version. Assume it affects up to that version
				if vulns.IsNotEmptyOrFiller(v.Version) {
					introduced = "0"
					lastaffected = v.Version
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
			if slices.Contains(versionInfo.AffectedVersions, possibleNewAffectedVersion) {
				// Avoid appending duplicates
				continue
			}
			versionInfo.AffectedVersions = append(versionInfo.AffectedVersions, possibleNewAffectedVersion)
		}
	}
	return gotVersions, notes
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

// Takes a CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(CVE cves.CVE5, references []cves.Reference, repos []string, cache git.RepoTagsCache, directory string) error {
	// Create a base OSV record
	cveID := CVE.Metadata.CVEID
	datePublished, _ := vulns.CVE5timestampToRFC3339(CVE.Metadata.DatePublished)
	dateUpdated, _ := vulns.CVE5timestampToRFC3339(CVE.Metadata.DateUpdated)
	metrics := CVE.Containers.CNA.Metrics

	v, notes := vulns.FromCVE(cveID, cveID, references, CVE.Containers.CNA.Descriptions, datePublished, dateUpdated, metrics)

	versions, versionNotes := ExtractVersionInfo(CVE, repos, http.DefaultClient)
	notes = append(notes, versionNotes...)

	// Attempt to resolve Version Info to commits.
	cna := CVE.Containers.CNA
	maybeVendorName := "UNKNOWN"
	maybeProductName := "UNKNOWN"
	for _, cveAff := range cna.Affected {
		if slices.Contains(VendorProductDenyList, cves.VendorProduct{Vendor: cveAff.Vendor, Product: cveAff.Product}) {
			continue
		}
		if vulns.IsNotEmptyOrFiller(cveAff.Vendor) {
			maybeVendorName = cveAff.Vendor
		}
		if vulns.IsNotEmptyOrFiller(cveAff.Product) {
			maybeProductName = cveAff.Product
		}
		if maybeProductName != "UNKNOWN" && maybeVendorName != "UNKNOWN" {
			break
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

	affected := vulns.Affected{}
	affected.AttachExtractedVersionInfo(versions)
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
	Logger.Warnf("numNotes %v", len(notes))
	notesFile := filepath.Join(vulnDir, v.ID+".notes")
	if len(notes) > 0 {
		Logger.Warnf("notes: %s", notesFile)
		err = os.WriteFile(notesFile, []byte(strings.Join(notes, "\n")), 0660)
		if err != nil {
			Logger.Warnf("[%s]: Failed to write %s: %v", CVE.Metadata.CVEID, notesFile, err)
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
	if !slices.Contains([]string{"OSV", "PackageInfo"}, *outFormat) {
		fmt.Fprintf(os.Stderr, "Unsupported output format: %s\n", *outFormat)
		os.Exit(1)
	}

	Metrics.Outcomes = make(map[cves.CVEID]ConversionOutcome)

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

		// TODO: Implement CVEToPackageInfo for CVEList CVE
		// case "PackageInfo":
		// 	err = CVEToPackageInfo(cve.CVE, ReposForCVE[CVEID], RepoTagsCache, *outDir)
		// }
		// Parse this error to determine which failure mode it was
		if err != nil {
			Logger.Warnf("[%s]: Failed to generate an OSV record: %+v", CVEID, err)
			if errors.Is(err, ErrNoRanges) {
				Metrics.Outcomes[CVEID] = NoRanges
			} else if errors.Is(err, ErrUnresolvedFix) {
				Metrics.Outcomes[CVEID] = FixUnresolvable
			} else {
				Metrics.Outcomes[CVEID] = ConversionUnknown
			}
		} else {

			Metrics.OSVRecordsGenerated++
			Metrics.Outcomes[CVEID] = Successful
		}
		// Metrics.TotalCVEs = len(parsed.Vulnerabilities)
		err = outputOutcomes(Metrics.Outcomes, ReposForCVE, *outDir)
		if err != nil {
			// Log entry with size 1.15M exceeds maximum size of 256.0K
			fmt.Fprintf(os.Stderr, "Failed to write out metrics: %v", err)
		}
		// Outcomes is too big to log, so zero it out.
		Metrics.Outcomes = nil
		Logger.Infof("%s Metrics: %+v", filepath.Base(*jsonPath), Metrics)
	}
}
