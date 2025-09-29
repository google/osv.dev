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
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	extension = ".json"
)

// ConversionMetrics holds the collected data about the conversion process for a single CVE.
type ConversionMetrics struct {
	CNA            string                          `json:"cna"`             // The CNA that assigned the CVE.
	Outcome        string                          `json:"outcome"`         // The final outcome of the conversion (e.g., "Successful", "Failed").
	Repos          []string                        `json:"repos"`           // A list of repositories extracted from the CVE's references.
	RefTypesCount  map[osvschema.ReferenceType]int `json:"ref_types_count"` // A count of each type of reference found.
	VersionSources []VersionSource                 `json:"version_sources"` // A list of the ways the versions were extracted
	Notes          []string                        `json:"notes"`           // A collection of notes and warnings generated during conversion.
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
func extractConversionMetrics(cve cves.CVE5, refs []osvschema.Reference, metrics *ConversionMetrics) {
	// Capture the CNA for heuristic analysis.
	metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis

	// Count number of references of each type
	refTypeCounts := make(map[osvschema.ReferenceType]int)
	for _, ref := range refs {
		refTypeCounts[ref.Type]++
	}
	metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		metrics.Notes = append(metrics.Notes, fmt.Sprintf("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count))
	}

	// TODO(jesslowe): Add more analysis based on ADP containers, CVSS, KEV, CWE, etc.
}

// FromCVE5 creates a `vulns.Vulnerability` object from a `cves.CVE5` object.
// It populates the main fields of the OSV record, including ID, summary, details,
// references, timestamps, severity, and version information.
func FromCVE5(cve cves.CVE5, refs []cves.Reference, metrics *ConversionMetrics) (*vulns.Vulnerability, []string) {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	var notes []string
	v := vulns.Vulnerability{
		Vulnerability: osvschema.Vulnerability{
			SchemaVersion: osvschema.SchemaVersion,
			ID:            string(cve.Metadata.CVEID),
			Summary:       cve.Containers.CNA.Title,
			Details:       cves.EnglishDescription(cve.Containers.CNA.Descriptions),
			Aliases:       aliases,
			Related:       related,
			References:    vulns.ClassifyReferences(refs),
		}}

	published, err := cves.ParseCVE5Timestamp(cve.Metadata.DatePublished)
	if err != nil {
		notes = append(notes, "Published date failed to parse, setting time to now")
		published = time.Now()
	}
	v.Published = published

	modified, err := cves.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		notes = append(notes, "Modified date failed to parse, setting time to now")
		modified = time.Now()
	}
	v.Modified = modified

	// Add affected version information.
	versionSources, versNotes := AddVersionInfo(cve, &v)
	notes = append(notes, versNotes...)
	metrics.VersionSources = versionSources
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
		if sev := vulns.FindSeverity(severity); sev != (osvschema.Severity{}) {
			v.Severity = []osvschema.Severity{sev}
		}
	}

	return &v, notes
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
	outputFile := filepath.Join(vulnDir, v.ID+extension)
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

// ConvertAndExportCVEToOSV is the main function for this file. It takes a CVE,
// converts it into an OSV record, collects metrics, and writes both to disk.
func ConvertAndExportCVEToOSV(cve cves.CVE5, directory string) error {
	cveID := cve.Metadata.CVEID
	cnaAssigner := cve.Metadata.AssignerShortName
	references := identifyPossibleURLs(cve)
	metrics := &ConversionMetrics{}
	// Create a base OSV record from the CVE.
	v, notes := FromCVE5(cve, references, metrics)
	metrics.Notes = append(metrics.Notes, notes...)

	// Collect metrics about the conversion.
	extractConversionMetrics(cve, v.References, metrics)

	// Try to extract repository URLs from references.
	repos, repoNotes := cves.ReposFromReferencesCVEList(string(cveID), references, RefTagDenyList)
	metrics.Notes = append(metrics.Notes, repoNotes...)
	metrics.Repos = repos

	vulnDir := filepath.Join(directory, cnaAssigner)

	// Save the OSV record to a file.
	if err := writeOSVToFile(cveID, cnaAssigner, vulnDir, v); err != nil {
		return err
	}

	// Save the conversion metrics to a file.
	if err := writeMetricToFile(cveID, vulnDir, metrics); err != nil {
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
