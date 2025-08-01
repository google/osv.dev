package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ConversionOutcome int

var ErrNoRanges = errors.New("no ranges")

var ErrUnresolvedFix = errors.New("fixes not resolved to commits")

// String returns the string representation of a ConversionOutcome.
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

// addIDToNotes prepends a CVE ID to a slice of notes.
func addIDToNotes(id cves.CVEID, notes []string) []string {
	var updatedNotes []string
	for _, note := range notes {
		updatedNotes = append(updatedNotes, fmt.Sprintf("[%s] %s", id, note))
	}
	return updatedNotes
}

// determineHeuristics examines a CVE and extracts metrics and heuristics about it.
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
}

// FromCVE5 creates a Vulnerability from a CVE5 object.
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
	// VERSIONS WILL BE ADDED IN ANOTHER PR
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

// CVEToOSV converts a CVE into an OSV finding and writes it to a file.
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
