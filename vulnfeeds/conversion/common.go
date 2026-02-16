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

	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
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

// Examines repos and tries to convert versions to commits by treating them as Git tags.
func GitVersionsToCommits(versionRanges []*osvschema.Range, repos []string, metrics *models.ConversionMetrics, cache *git.RepoTagsCache) ([]*osvschema.Range, []*osvschema.Range, []string) {
	var newVersionRanges []*osvschema.Range
	unresolvedRanges := versionRanges
	var successfulRepos []string

	for _, repo := range repos {
		if len(unresolvedRanges) == 0 {
			break // All ranges have been resolved.
		}
		if cache.IsInvalid(repo) {
			continue
		}
		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			metrics.AddNote("Failed to normalize tags - %s", repo)
			continue
		}

		var stillUnresolvedRanges []*osvschema.Range
		for _, vr := range unresolvedRanges {
			var introduced, fixed, lastAffected string
			for _, e := range vr.GetEvents() {
				if e.GetIntroduced() != "" {
					introduced = e.GetIntroduced()
				}
				if e.GetFixed() != "" {
					fixed = e.GetFixed()
				}
				if e.GetLastAffected() != "" {
					lastAffected = e.GetLastAffected()
				}
			}

			var introducedCommit string
			if introduced == "0" {
				introducedCommit = "0"
			} else {
				introducedCommit = resolveVersionToCommit(introduced, normalizedTags)
			}
			fixedCommit := resolveVersionToCommit(fixed, normalizedTags)
			lastAffectedCommit := resolveVersionToCommit(lastAffected, normalizedTags)

			if introducedCommit != "" && (fixedCommit != "" || lastAffectedCommit != "") {
				var newVR *osvschema.Range

				if fixedCommit != "" {
					newVR = BuildVersionRange(introducedCommit, "", fixedCommit)
				} else {
					newVR = BuildVersionRange(introducedCommit, lastAffectedCommit, "")
				}
				successfulRepos = append(successfulRepos, repo)
				newVR.Repo = repo
				newVR.Type = osvschema.Range_GIT
				if len(vr.GetEvents()) > 0 {
					databaseSpecific, err := utility.NewStructpbFromMap(map[string]any{"versions": vr.GetEvents()})
					if err != nil {
						metrics.AddNote("failed to make database specific: %v", err)
					} else {
						newVR.DatabaseSpecific = databaseSpecific
					}
				}

				newVersionRanges = append(newVersionRanges, newVR)
			} else {
				stillUnresolvedRanges = append(stillUnresolvedRanges, vr)
			}
		}
		unresolvedRanges = stillUnresolvedRanges
	}

	if len(newVersionRanges) > 0 {
		metrics.ResolvedRangesCount += len(newVersionRanges)
		metrics.Outcome = models.Successful
	}

	if len(unresolvedRanges) > 0 {
		metrics.UnresolvedRangesCount += len(unresolvedRanges)
		if len(newVersionRanges) == 0 {
			metrics.Outcome = models.NoCommitRanges
		}
	}

	return newVersionRanges, unresolvedRanges, successfulRepos
}

// resolveVersionToCommit is a helper to convert a version string to a commit hash.
// It logs the outcome of the conversion attempt and returns an empty string on failure.
func resolveVersionToCommit(version string, normalizedTags map[string]git.NormalizedTag) string {
	if version == "" {
		return ""
	}
	commit, err := git.VersionToCommit(version, normalizedTags)
	if err != nil {
		return ""
	}

	return commit
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

func MergeTwoRanges(range1, range2 *osvschema.Range) *osvschema.Range {
	// check if the ranges are the same
	if range1.Repo != range2.Repo || range1.Type != range2.Type {
		return nil
	}

	mergedRange := &osvschema.Range{
		Repo:   range1.Repo,
		Type:   range1.Type,
		Events: append(range1.Events, range2.Events...),
	}

	db1 := range1.GetDatabaseSpecific()
	db2 := range2.GetDatabaseSpecific()

	if db1 == nil && db2 == nil {
		return mergedRange
	}

	mergedMap := make(map[string]any)

	if db1 != nil {
		for k, v := range db1.GetFields() {
			mergedMap[k] = v.AsInterface()
		}
	}

	if db2 != nil {
		for k, v := range db2.GetFields() {
			if existing, ok := mergedMap[k]; ok {
				// If both are lists, append them
				if list1, ok := existing.([]any); ok {
					if list2, ok := v.AsInterface().([]any); ok {
						mergedMap[k] = append(list1, list2...)
						continue
					}
				}
			}
			// Otherwise overwrite or add new
			mergedMap[k] = v.AsInterface()
		}
	}

	if len(mergedMap) > 0 {
		if ds, err := utility.NewStructpbFromMap(mergedMap); err == nil {
			mergedRange.DatabaseSpecific = ds
		} else {
			logger.Warn("Failed to create DatabaseSpecific for merged range: %v", err)
		}
	}

	return mergedRange
}
