// Package conversion implements common utilities for converting vulnerability data
// from various sources into the OSV schema.
package conversion

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
