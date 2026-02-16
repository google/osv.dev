// Package conversion implements common utilities for converting vulnerability data
// from various sources into the OSV schema.
package conversion

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
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


// resolveVersionToCommit is a helper to convert a version string to a commit hash.
// It logs the outcome of the conversion attempt and returns an empty string on failure.
func resolveVersionToCommit(cveID models.CVEID, version, versionType, repo string, normalizedTags map[string]git.NormalizedTag) string {
	if version == "" {
		return ""
	}
	logger.Info("Attempting to resolve version to commit", slog.String("cve", string(cveID)), slog.String("version", version), slog.String("type", versionType), slog.String("repo", repo))
	commit, err := git.VersionToCommit(version, normalizedTags)
	if err != nil {
		logger.Warn("Failed to get Git commit for version", slog.String("cve", string(cveID)), slog.String("version", version), slog.String("type", versionType), slog.String("repo", repo), slog.Any("err", err))
		return ""
	}
	logger.Info("Successfully derived commit for version", slog.String("cve", string(cveID)), slog.String("commit", commit), slog.String("version", version), slog.String("type", versionType))

	return commit
}

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), VersionInfo with AffectedVersions and
// typically no AffectedCommits and attempts to add AffectedCommits (including Fixed commits) where there aren't any.
// Refuses to add the same commit to AffectedCommits more than once.
func gitVersionsToCommits(cveID models.CVEID, versionRanges []*osvschema.Range, repos []string, metrics *models.ConversionMetrics, cache *git.RepoTagsCache) (*osvschema.Affected, error) {
	var newAff osvschema.Affected
	var newVersionRanges []*osvschema.Range
	unresolvedRanges := versionRanges

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
				introducedCommit = resolveVersionToCommit(cveID, introduced, "introduced", repo, normalizedTags)
			}
			fixedCommit := resolveVersionToCommit(cveID, fixed, "fixed", repo, normalizedTags)
			lastAffectedCommit := resolveVersionToCommit(cveID, lastAffected, "last_affected", repo, normalizedTags)

			if introducedCommit != "" && (fixedCommit != "" || lastAffectedCommit != "") {
				var newVR *osvschema.Range

				if fixedCommit != "" {
					newVR = cves.BuildVersionRange(introducedCommit, "", fixedCommit)
				} else {
					newVR = cves.BuildVersionRange(introducedCommit, lastAffectedCommit, "")
				}

				newVR.Repo = repo
				newVR.Type = osvschema.Range_GIT
				if len(vr.GetEvents()) > 0 {
					databaseSpecific, err := utility.NewStructpbFromMap(map[string]any{"versions": vr.GetEvents()})
					if err != nil {
						logger.Warn("failed to make database specific: %v", err)
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

	var err error
	if len(unresolvedRanges) > 0 {
		databaseSpecific, err := utility.NewStructpbFromMap(map[string]any{"unresolved_ranges": unresolvedRanges})
		if err != nil {
			logger.Warn("failed to make database specific: %v", err)
		} else {
			newAff.DatabaseSpecific = databaseSpecific
		}

		metrics.UnresolvedRangesCount += len(unresolvedRanges)
	}

	if len(newVersionRanges) > 0 {
		newAff.Ranges = newVersionRanges
		metrics.ResolvedRangesCount += len(newVersionRanges)
	} else if len(unresolvedRanges) > 0 { // Only error if there were ranges to resolve but none were.
		err = errors.New("was not able to get git version ranges")
	}

	return &newAff, err
}