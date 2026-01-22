package conversion

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// AddAffected adds an osvschema.Affected to a vulnerability, ensuring that no duplicate ranges are added.
func AddAffected(v *vulns.Vulnerability, aff *osvschema.Affected, metrics *models.ConversionMetrics) {
	allExistingRanges := make(map[string]struct{})
	for _, existingAff := range v.Affected {
		for _, r := range existingAff.GetRanges() {
			rangeBytes, err := json.Marshal(r)
			if err == nil {
				allExistingRanges[string(rangeBytes)] = struct{}{}
			}
		}
	}

	uniqueRanges := []*osvschema.Range{}
	for _, r := range aff.GetRanges() {
		rangeBytes, err := json.Marshal(r)
		if err != nil {
			metrics.AddNote("Could not marshal range to check for duplicates, adding anyway: %+v", r)
			uniqueRanges = append(uniqueRanges, r)

			continue
		}
		rangeStr := string(rangeBytes)
		if _, exists := allExistingRanges[rangeStr]; !exists {
			uniqueRanges = append(uniqueRanges, r)
			allExistingRanges[rangeStr] = struct{}{}
		} else {
			metrics.AddNote("Skipping duplicate range: %+v", r)
		}
	}

	if len(uniqueRanges) > 0 {
		newAff := &osvschema.Affected{
			Package:          aff.GetPackage(),
			Ranges:           uniqueRanges,
			DatabaseSpecific: aff.GetDatabaseSpecific(),
		}
		v.Affected = append(v.Affected, newAff)
	}
}

func DeduplicateRefs(refs []models.Reference) []models.Reference {
	// Deduplicate references by URL.
	slices.SortStableFunc(refs, func(a, b models.Reference) int {
		return strings.Compare(a.URL, b.URL)
	})
	refs = slices.CompactFunc(refs, func(a, b models.Reference) bool {
		return a.URL == b.URL
	})

	return refs
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
