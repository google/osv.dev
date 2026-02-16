// Package conversion implements common utilities for converting vulnerability data
// from various sources into the OSV schema.
package conversion

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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

// ConductAnalysis conducts an analysis of the conversion results after completion by reading
// all of the .metrics.json files and extracting conversion outcomes.
func ConductAnalysis(year string, dir string) {
	// get the current time in minutes
	currentTime := time.Now().Format("2006-01-02T15:04")
	outcomesCSV := "nvd-conversion-outcomes-" + year + "-" + currentTime + ".csv"
	csvFile, err := os.Create(filepath.Join(dir, outcomesCSV))
	if err != nil {
		logger.Fatal("Failed to create analysis CSV file", slog.Any("err", err))
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	header := []string{"CVEID", "Outcome"}
	if err := csvWriter.Write(header); err != nil {
		logger.Fatal("Failed to write header to CSV", slog.Any("err", err))
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".metrics.json") {
			data, err := os.ReadFile(path)
			if err != nil {
				logger.Warn("Failed to read metrics file", slog.String("path", path), slog.Any("err", err))
				return nil // Continue
			}

			var metrics models.ConversionMetrics
			if err := json.Unmarshal(data, &metrics); err != nil {
				logger.Warn("Failed to unmarshal metrics JSON", slog.String("path", path), slog.Any("err", err))
				return nil // Continue
			}

			record := []string{
				string(metrics.CVEID),
				metrics.Outcome.String(),
			}
			if err := csvWriter.Write(record); err != nil {
				logger.Warn("Failed to write record to CSV", slog.String("cve", string(metrics.CVEID)), slog.Any("err", err))
			}
		}

		return nil
	})

	if err != nil {
		logger.Error("Failed to walk directory for analysis", slog.Any("err", err))
	}
}

// CreateMetricsFile creates the initial file for the metrics record.
func CreateMetricsFile(id models.CVEID, vulnDir string) (*os.File, error) {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics"+models.Extension)
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

func WriteMetricsFile(metrics *models.ConversionMetrics, metricsFile *os.File) error {
	marshalledMetrics, err := json.MarshalIndent(&metrics, "", "  ")
	if err != nil {
		logger.Info("Failed to marshal", slog.Any("err", err))
		return err
	}

	_, err = metricsFile.Write(marshalledMetrics)
	if err != nil {
		logger.Warn("Failed to write", slog.String("path", metricsFile.Name()), slog.Any("err", err))
		return fmt.Errorf("failed to write %s: %w", metricsFile.Name(), err)
	}

	metricsFile.Close()

	return nil
}

// BuildVersionRange is a helper function that adds 'introduced', 'fixed', or 'last_affected'
// events to an OSV version range. If 'intro' is empty, it defaults to "0".
func BuildVersionRange(intro string, lastAff string, fixed string) *osvschema.Range {
	var versionRange osvschema.Range
	var i string
	if intro == "" {
		i = "0"
	} else {
		i = intro
	}
	versionRange.Events = append(versionRange.Events, &osvschema.Event{
		Introduced: i})

	if fixed != "" {
		versionRange.Events = append(versionRange.Events, &osvschema.Event{
			Fixed: fixed})
	} else if lastAff != "" {
		versionRange.Events = append(versionRange.Events, &osvschema.Event{
			LastAffected: lastAff,
		})
	}

	return &versionRange
}
