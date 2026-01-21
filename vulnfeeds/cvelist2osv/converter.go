// Package cvelist2osv converts a single given CVEList JSON to OSV format.
package cvelist2osv

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// extractConversionMetrics examines a CVE and its generated OSV references to populate
// the ConversionMetrics struct with heuristics about the conversion process.
// It captures the assigning CNA and counts the occurrences of each reference type.
func extractConversionMetrics(cve models.CVE5, refs []*osvschema.Reference, metrics *models.ConversionMetrics) {
	// Capture the CNA for heuristic analysis.
	metrics.CNA = cve.Metadata.AssignerShortName
	// TODO(jesslowe): more CNA based analysis

	// Count number of references of each type
	refTypeCounts := make(map[osvschema.Reference_Type]int)
	for _, ref := range refs {
		refTypeCounts[ref.GetType()]++
	}
	metrics.RefTypesCount = refTypeCounts
	for refType, count := range refTypeCounts {
		metrics.AddNote("[%s]: Reference Type %s: %d", cve.Metadata.CVEID, refType, count)
	}

	// TODO(jesslowe): Add more analysis based on ADP containers, CVSS, KEV, CWE, etc.
}

// getCWEs extracts and adds CWE IDs from the CVE5 problem-types
func getCWEs(cna models.CNA, metrics *models.ConversionMetrics) []string {
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
		return nil
	}

	// Sort and remove duplicates
	slices.Sort(cwes)
	cwes = slices.Compact(cwes)

	metrics.AddNote("Extracted CWEIDs: %v", cwes)

	return cwes
}

// FromCVE5 creates a `vulns.Vulnerability` object from a `models.CVE5` object.
// It populates the main fields of the OSV record, including ID, summary, details,
// references, timestamps, severity, and version information.
func FromCVE5(cve models.CVE5, refs []models.Reference, metrics *models.ConversionMetrics, sourceLink string) *vulns.Vulnerability {
	aliases, related := vulns.ExtractReferencedVulns(cve.Metadata.CVEID, cve.Metadata.CVEID, refs)
	v := vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{
			SchemaVersion: osvconstants.SchemaVersion,
			Id:            string(cve.Metadata.CVEID),
			Summary:       cve.Containers.CNA.Title,
			Details:       models.EnglishDescription(cve.Containers.CNA.Descriptions),
			Aliases:       aliases,
			Related:       related,
			References:    vulns.ClassifyReferences(refs),
		}}

	published, err := models.ParseCVE5Timestamp(cve.Metadata.DatePublished)
	if err != nil {
		metrics.AddNote("[%s]: Published date failed to parse, setting time to now", cve.Metadata.CVEID)
		published = time.Now()
	}
	v.Published = timestamppb.New(published)

	modified, err := models.ParseCVE5Timestamp(cve.Metadata.DateUpdated)
	if err != nil {
		metrics.AddNote("[%s]: Modified date failed to parse, setting time to now", cve.Metadata.CVEID)
		modified = time.Now()
	}
	v.Modified = timestamppb.New(modified)

	// Try to extract repository URLs from references.
	repos, repoNotes := cves.ReposFromReferencesCVEList(string(cve.Metadata.CVEID), refs, models.RefTagDenyList)
	for _, note := range repoNotes {
		metrics.AddNote("%s", note)
	}
	metrics.Repos = repos

	// Create a map to hold DatabaseSpecific fields
	dbSpecific := buildDBSpecific(cve, metrics, sourceLink)

	if len(dbSpecific) > 0 {
		databaseSpecific, err := utility.NewStructpbFromMap(dbSpecific)
		if err != nil {
			metrics.AddNote("Failed to convert database specific: %v", err)
		} else {
			v.DatabaseSpecific = databaseSpecific
		}
	}

	// Sort references for deterministic output
	sort.Slice(v.References, func(i, j int) bool {
		if v.References[i].GetUrl() != v.References[j].GetUrl() {
			return v.References[i].GetUrl() < v.References[j].GetUrl()
		}

		return v.References[i].GetType() < v.References[j].GetType()
	})

	// Combine severity metrics from both CNA and ADP containers.
	var severity []models.Metrics
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

	return &v
}

// CreateOSVFile creates the initial file for the OSV record.
func CreateOSVFile(id models.CVEID, vulnDir string) (*os.File, error) {
	outputFile := filepath.Join(vulnDir, string(id)+models.Extension)

	f, err := os.Create(outputFile)
	if err != nil {
		logger.Info("Failed to open for writing "+outputFile, slog.String("cve", string(id)), slog.String("path", outputFile), slog.Any("err", err))
		return nil, err
	}

	return f, err
}

// CreateMetricsFile saves the collected conversion metrics to a JSON file.
// This file provides data for analyzing the success and characteristics of the
// conversion process for a given CVE.
func CreateMetricsFile(id models.CVEID, vulnDir string) (*os.File, error) {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics.json")
	f, err := os.Create(metricsFile)
	if err != nil {
		logger.Info("Failed to open for writing "+metricsFile, slog.String("cve", string(id)), slog.String("path", metricsFile), slog.Any("err", err))
		return nil, err
	}

	return f, nil
}

// ConvertAndExportCVEToOSV is the main function for this file. It takes a CVE,
// converts it into an OSV record, collects metrics, and writes both to disk.
func ConvertAndExportCVEToOSV(cve models.CVE5, vulnSink io.Writer, metricsSink io.Writer, sourceLink string) error {
	cveID := cve.Metadata.CVEID
	cnaAssigner := cve.Metadata.AssignerShortName
	references := identifyPossibleURLs(cve)

	// Add NVD and computed source link to references
	references = append(references, models.Reference{URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)})
	if sourceLink != "" {
		references = append(references, models.Reference{URL: sourceLink})
	}

	references = deduplicateRefs(references)

	metrics := models.ConversionMetrics{CVEID: cveID, CNA: cnaAssigner, UnresolvedRangesCount: 0, ResolvedRangesCount: 0}

	// Create a base OSV record from the CVE.
	v := FromCVE5(cve, references, &metrics, sourceLink)

	// Collect metrics about the conversion.
	extractConversionMetrics(cve, v.References, &metrics)

	// Add affected version information.
	versionExtractor := GetVersionExtractor(cve.Metadata.AssignerShortName)
	versionExtractor.ExtractVersions(cve, v, &metrics, metrics.Repos)

	groupAffectedRanges(v.Affected)

	models.DetermineOutcome(&metrics)

	err := v.ToJSON(vulnSink)
	if err != nil {
		logger.Info("Failed to write", slog.Any("err", err))
		return err
	}

	marshalledMetrics, err := json.MarshalIndent(&metrics, "", "  ")
	if err != nil {
		logger.Info("Failed to marshal", slog.Any("err", err))
		return err
	}
	_, err = metricsSink.Write(marshalledMetrics)
	if err != nil {
		logger.Info("Failed to write", slog.Any("err", err))
		return err
	}

	return nil
}

// identifyPossibleURLs extracts all URLs from a CVE object.
// It searches for URLs in the CNA and ADP reference sections, as well as in
// the 'collectionUrl' and 'repo' fields of the 'affected' entries.
func identifyPossibleURLs(cve models.CVE5) []models.Reference {
	refs := cve.Containers.CNA.References

	for _, adp := range cve.Containers.ADP {
		if adp.References != nil {
			refs = append(refs, adp.References...)
		}
	}

	for _, affected := range cve.Containers.CNA.Affected {
		if affected.CollectionURL != "" {
			refs = append(refs, models.Reference{URL: affected.CollectionURL})
		}
		if affected.Repo != "" {
			refs = append(refs, models.Reference{URL: affected.Repo})
		}
	}

	// Filter out empty URLs from CNA references if any
	filteredRefs := make([]models.Reference, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			filteredRefs = append(filteredRefs, ref)
		}
	}
	refs = filteredRefs

	return refs
}

func deduplicateRefs(refs []models.Reference) []models.Reference {
	// Deduplicate references by URL.
	slices.SortStableFunc(refs, func(a, b models.Reference) int {
		return strings.Compare(a.URL, b.URL)
	})
	refs = slices.CompactFunc(refs, func(a, b models.Reference) bool {
		return a.URL == b.URL
	})

	return refs
}

func buildDBSpecific(cve models.CVE5, metrics *models.ConversionMetrics, sourceLink string) map[string]any {
	dbSpecific := make(map[string]any)

	if sourceLink != "" {
		dbSpecific["osv_generated_from"] = sourceLink
	} else {
		dbSpecific["osv_generated_from"] = "unknown"
	}

	if cve.Metadata.AssignerShortName != "" {
		dbSpecific["cna_assigner"] = cve.Metadata.AssignerShortName
	}

	if slices.Contains(cve.Containers.CNA.Tags, "disputed") {
		dbSpecific["isDisputed"] = true
	}

	cwes := getCWEs(cve.Containers.CNA, metrics)
	if len(cwes) > 0 {
		dbSpecific["cwe_ids"] = cwes
	}

	return dbSpecific
}
