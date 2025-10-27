// Package cvelist2osv converts a single given CVEList JSON to OSV format.
package cvelist2osv

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	extension = ".json"
)

// ConversionMetrics holds the collected data about the conversion process for a single CVE.
type ConversionMetrics struct {
	CVEID                 cves.CVEID                       `json:"id"`              // The CVE ID
	CNA                   string                           `json:"cna"`             // The CNA that assigned the CVE.
	Outcome               ConversionOutcome                `json:"outcome"`         // The final outcome of the conversion (e.g., "Successful", "Failed").
	Repos                 []string                         `json:"repos"`           // A list of repositories extracted from the CVE's references.
	RefTypesCount         map[osvschema.Reference_Type]int `json:"ref_types_count"` // A count of each type of reference found.
	VersionSources        []VersionSource                  `json:"version_sources"` // A list of the ways the versions were extracted
	Notes                 []string                         `json:"notes"`           // A collection of notes and warnings generated during conversion.
	CPEs                  []string                         `json:"cpes"`
	UnresolvedRangesCount int                              `json:"unresolved_ranges_count"`
	ResolvedRangesCount   int                              `json:"resolved_ranges_count"`
}

// AddNote adds a formatted note to the ConversionMetrics.
func (m *ConversionMetrics) AddNote(format string, a ...any) {
	m.Notes = append(m.Notes, fmt.Sprintf(format, a...))
	logger.Debug(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
}

// AddSource appends a source to the ConversionMetrics
func (m *ConversionMetrics) AddSource(source VersionSource) {
	m.VersionSources = append(m.VersionSources, source)
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
// the ConversionMetrics struct with heuristics about the conversion process.
// It captures the assigning CNA and counts the occurrences of each reference type.
func extractConversionMetrics(cve cves.CVE5, refs []*osvschema.Reference, metrics *ConversionMetrics) {
	// Capture the CNA for heuristic analysis.
	metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis

	// Count number of references of each type
	refTypeCounts := make(map[osvschema.Reference_Type]int)
	for _, ref := range refs {
		refTypeCounts[ref.Type]++
	}
	metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		metrics.AddNote("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count)
	}

	// TODO(jesslowe): Add more analysis based on ADP containers, CVSS, KEV, CWE, etc.
}

// attachCWEs extracts and adds CWE IDs from the CVE5 problem-types
func attachCWEs(v *vulns.Vulnerability, cna cves.CNA, metrics *ConversionMetrics) {
	var cwes []string

	for _, pt := range cna.ProblemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CWEID == "" {
				continue
			}
			cwes = append(cwes, desc.CWEID)
		}
	}
	if len(cwes) == 0 {
		return
	}

	// Sort and remove duplicates
	slices.Sort(cwes)
	cwes = slices.Compact(cwes)

	if v.DatabaseSpecific == nil {
		v.DatabaseSpecific = &structpb.Struct{Fields: make(map[string]*structpb.Value)}
	}

	// Add CWEs to DatabaseSpecific for consistency with GHSA schema.
	cweList := make([]*structpb.Value, 0, len(cwes))
	for _, cwe := range cwes {
		cweList = append(cweList, structpb.NewStringValue(cwe))
	}
	v.DatabaseSpecific.Fields["cwe_ids"] = structpb.NewListValue(&structpb.ListValue{Values: cweList})

	metrics.AddNote("Extracted CWEIDs: %v", cwes)
}

// FromCVE5 creates a `vulns.Vulnerability` object from a `cves.CVE5` object.
// It populates the main fields of the OSV record, including ID, summary, details,
// references, timestamps, severity, and version information.
func FromCVE5(cve cves.CVE5, refs []cves.Reference, metrics *ConversionMetrics) *vulns.Vulnerability {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	v := vulns.Vulnerability{
		Vulnerability: osvschema.Vulnerability{
			SchemaVersion: osvconstants.SchemaVersion,
			Id:            string(cve.Metadata.CVEID),
			Summary:       cve.Containers.CNA.Title,
			Details:       cves.EnglishDescription(cve.Containers.CNA.Descriptions),
			Aliases:       aliases,
			Related:       related,
			References:    vulns.ClassifyReferences(refs),
		}}

	published, err := cves.ParseCVE5Timestamp(cve.Metadata.DatePublished)
	if err != nil {
		metrics.AddNote("[%s]: Published date failed to parse, setting time to now", cve.Metadata.CVEID)
		published = time.Now()
	}
	v.Published = timestamppb.New(published)

	modified, err := cves.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		metrics.AddNote("[%s]: Modified date failed to parse, setting time to now", cve.Metadata.CVEID)
		modified = time.Now()
	}
	v.Modified = timestamppb.New(modified)

	// Try to extract repository URLs from references.
	repos, repoNotes := cves.ReposFromReferencesCVEList(string(cve.Metadata.CVEID), refs, RefTagDenyList)
	for _, note := range repoNotes {
		metrics.AddNote("%s", note)
	}
	metrics.Repos = repos

	if slices.Contains(cve.Containers.CNA.Tags, "disputed") {
		if v.DatabaseSpecific == nil {
			v.DatabaseSpecific = &structpb.Struct{Fields: make(map[string]*structpb.Value)}
		}
		v.DatabaseSpecific.Fields["isDisputed"] = structpb.NewBoolValue(true)
	}

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
		if sev := vulns.FindSeverity(severity); sev != nil {
			v.Severity = []*osvschema.Severity{sev}
		}
	}

	// attachCWEs extract and adds the cwes from the CVE5 Problem-types
	attachCWEs(&v, cve.Containers.CNA, metrics)

	return &v
}

// writeOSVToFile saves the generated OSV vulnerability record to a JSON file.
// The file is named after the vulnerability ID and placed in a subdirectory
// named after the assigning CNA.
func writeOSVToFile(id cves.CVEID, cnaAssigner string, vulnDir string, v *vulns.Vulnerability) error {
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		logger.Warn("Failed to create dir", slog.Any("err", err))
		return fmt.Errorf("failed to create dir: %w", err)
	}
	outputFile := filepath.Join(vulnDir, v.Id+extension)
	f, err := os.Create(outputFile)
	if err != nil {
		logger.Info("Failed to open for writing "+outputFile, slog.String("cve", string(id)), slog.String("path", outputFile), slog.Any("err", err))
		return err
	}
	defer f.Close()

	err = v.ToJSON(f)
	if err != nil {
		logger.Info("Failed to write "+outputFile, slog.String("path", outputFile), slog.Any("err", err))
	} else {
		logger.Info("Generated OSV record for "+string(id), slog.String("cve", string(id)), slog.String("cna", cnaAssigner))
	}

	return err
}

// writeMetricToFile saves the collected conversion metrics to a JSON file.
// This file provides data for analyzing the success and characteristics of the
// conversion process for a given CVE.
func writeMetricToFile(id cves.CVEID, vulnDir string, metrics *ConversionMetrics) error {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics.json")
	marshalledMetrics, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		logger.Warn("Failed to marshal metrics for "+string(id), slog.String("cve", string(id)), slog.Any("err", err))
		return err
	}
	if err = os.WriteFile(metricsFile, marshalledMetrics, 0600); err != nil {
		logger.Warn("Failed to write "+metricsFile, slog.String("cve", string(id)), slog.String("path", metricsFile), slog.Any("err", err))
		return err
	}

	return nil
}

func determineOutcome(metrics *ConversionMetrics) {
	// check if we have affected ranges/versions.
	if len(metrics.Repos) == 0 {
		// Fix unlikely, as no repos to resolve
		metrics.Outcome = NoRepos
		return
	}

	if metrics.ResolvedRangesCount > 0 {
		metrics.Outcome = Successful
	} else if metrics.UnresolvedRangesCount > 0 {
		metrics.Outcome = NoCommitRanges
	} else {
		metrics.Outcome = NoRanges
	}
}

// ConvertAndExportCVEToOSV is the main function for this file. It takes a CVE,
// converts it into an OSV record, collects metrics, and writes both to disk.
func ConvertAndExportCVEToOSV(cve cves.CVE5, directory string) error {
	cveID := cve.Metadata.CVEID
	cnaAssigner := cve.Metadata.AssignerShortName
	references := identifyPossibleURLs(cve)
	metrics := ConversionMetrics{CVEID: cveID, CNA: cnaAssigner, UnresolvedRangesCount: 0, ResolvedRangesCount: 0}

	// Create a base OSV record from the CVE.
	v := FromCVE5(cve, references, &metrics)

	// Collect metrics about the conversion.
	extractConversionMetrics(cve, v.References, &metrics)

	// Add affected version information.
	versionExtractor := GetVersionExtractor(cve.Metadata.AssignerShortName)
	versionExtractor.ExtractVersions(cve, v, &metrics, metrics.Repos)

	determineOutcome(&metrics)

	vulnDir := filepath.Join(directory, cnaAssigner)

	// Save the OSV record to a file.
	if err := writeOSVToFile(cveID, cnaAssigner, vulnDir, v); err != nil {
		return err
	}

	// Save the conversion metrics to a file.
	if err := writeMetricToFile(cveID, vulnDir, &metrics); err != nil {
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
		if affected.CollectionURL != "" {
			refs = append(refs, cves.Reference{URL: affected.CollectionURL})
		}
		if affected.Repo != "" {
			refs = append(refs, cves.Reference{URL: affected.Repo})
		}
	}

	// Deduplicate references by URL.
	slices.SortStableFunc(refs, func(a, b cves.Reference) int {
		return strings.Compare(a.URL, b.URL)
	})
	refs = slices.CompactFunc(refs, func(a, b cves.Reference) bool {
		return a.URL == b.URL
	})

	return refs
}
