package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	extension = ".json"
)

var (
	jsonPath = flag.String("cve_json", "", "Path to CVEList JSON to examine.")
	outDir   = flag.String("out_dir", "", "Path to output results.")
)
var Logger utility.LoggerWrapper
var RepoTagsCache git.RepoTagsCache
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
		notes = append(notes, "Published date failed to parse, setting time to now")
		v.Published = time.Now()
	}
	v.Modified, err = cves.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		notes = append(notes, "Modified date failed to parse, setting time to now")
		v.Modified = time.Now()
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
	for _, s := range severity {
		v.AddSeverity(s)
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

// CVEToOSV converts a CVE into an OSV finding and writes it to a file.
func CVEToOSV(CVE cves.CVE5, directory string) error {
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

	err = CVEToOSV(cve, *outDir)

	if err != nil {
		Logger.Warnf("[%s]: Failed to generate an OSV record: %+v", cve.Metadata.CVEID, err)
		Metrics.Outcome = "Failed"
	} else {
		Metrics.Outcome = "Successful"
	}
}
