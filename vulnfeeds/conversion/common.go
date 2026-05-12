// Package conversion implements common utilities for converting vulnerability data
// from various sources into the OSV schema.
package conversion

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
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
	refs = slices.Clone(refs)
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

	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Fatal("Failed to create output directory for analysis CSV file", slog.Any("err", err))
	}

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

// GitVersionsToCommits examines repos and tries to convert versions to commits by treating them as Git tags.
// Returns the resolved ranges, unresolved ranges, and successful repos involved.
func GitVersionsToCommits(versionRanges []models.RangeWithMetadata, repos []string, metrics *models.ConversionMetrics, cache git.RepoTagsCache) ([]models.RangeWithMetadata, []models.RangeWithMetadata, []string) {
	var newVersionRanges []models.RangeWithMetadata
	unresolvedRanges := versionRanges
	var successfulRepos []string

	for _, repo := range repos {
		if len(unresolvedRanges) == 0 {
			break // All ranges have been resolved.
		}
		if cache.IsInvalid(repo) {
			continue
		}

		repo, err := git.FindCanonicalLink(repo, http.DefaultClient, cache)
		if err != nil {
			metrics.AddNote("Failed to find canonical link - %s %v", repo, err)
			if errors.Is(err, git.ErrRateLimit) || strings.Contains(err.Error(), "429") {
				metrics.Outcome = models.Error
				return nil, nil, nil
			}

			continue
		}

		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			if errors.Is(err, git.ErrRateLimit) || strings.Contains(err.Error(), "429") {
				metrics.Outcome = models.Error
				return nil, nil, nil
			}
			metrics.AddNote("Failed to normalize tags - %s", repo)

			continue
		}

		var stillUnresolvedRanges []models.RangeWithMetadata
		for _, vr := range unresolvedRanges {
			var introduced, fixed, lastAffected string
			for _, e := range vr.Range.GetEvents() {
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
				introducedCommit, err = git.VersionToCommit(introduced, normalizedTags)
				if err != nil {
					metrics.AddNote("error resolving version to commit - %s - %s", introduced, err)
				}
			}
			fixedCommit, err := git.VersionToCommit(fixed, normalizedTags)
			if err != nil {
				metrics.AddNote("error resolving version to commit - %s - %s", fixed, err)
			}
			lastAffectedCommit, err := git.VersionToCommit(lastAffected, normalizedTags)
			if err != nil {
				metrics.AddNote("error resolving version to commit - %s - %s", lastAffected, err)
			}

			if fixedCommit != "" || lastAffectedCommit != "" {
				var newVR *osvschema.Range

				if fixedCommit != "" {
					newVR = BuildGitVersionRange(introducedCommit, "", fixedCommit, repo)
				} else {
					newVR = BuildGitVersionRange(introducedCommit, lastAffectedCommit, "", repo)
				}
				successfulRepos = append(successfulRepos, repo)
				if len(vr.Range.GetEvents()) > 0 {
					dbSpecificMap := map[string]any{
						"extracted_events": vr.Range.GetEvents(),
					}
					if vr.Metadata.CPE != "" {
						dbSpecificMap["cpe"] = vr.Metadata.CPE
					}
					if string(vr.Metadata.Source) != "" {
						dbSpecificMap["source"] = string(vr.Metadata.Source)
					}
					databaseSpecific, err := utility.NewStructpbFromMap(dbSpecificMap)
					if err != nil {
						metrics.AddNote("failed to make database specific: %v", err)
					} else {
						newVR.DatabaseSpecific = databaseSpecific
					}
				}

				newVersionRanges = append(newVersionRanges, models.RangeWithMetadata{
					Range:    newVR,
					Metadata: vr.Metadata,
				})
			} else {
				stillUnresolvedRanges = append(stillUnresolvedRanges, vr)
			}
		}
		unresolvedRanges = stillUnresolvedRanges
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

func BuildGitVersionRange(intro string, lastAff string, fixed string, repo string) *osvschema.Range {
	versionRange := BuildVersionRange(intro, lastAff, fixed)
	versionRange.Repo = repo
	versionRange.Type = osvschema.Range_GIT

	return versionRange
}

// MergeTwoRanges combines two osvschema.Range objects into a single range.
// It merges the events and the DatabaseSpecific fields. If the ranges are
// not for the same repository or are of different types, it returns an error.
// When merging DatabaseSpecific fields, it handles lists, maps, and simple
// strings. If there are mismatching types for the same key, it returns an error.
func MergeTwoRanges(range1, range2 *osvschema.Range) (*osvschema.Range, error) {
	// check if the ranges are the same
	if range1.GetRepo() != range2.GetRepo() || range1.GetType() != range2.GetType() {
		// return an error if not the case
		return nil, errors.New("ranges are not the same repo or type")
	}

	mergedRange := &osvschema.Range{
		Repo:   range1.GetRepo(),
		Type:   range1.GetType(),
		Events: append(range1.Events, range2.GetEvents()...),
	}

	db1 := range1.GetDatabaseSpecific()
	db2 := range2.GetDatabaseSpecific()

	if db1 == nil && db2 == nil {
		return mergedRange, nil
	}

	mergedMap := make(map[string]any)

	if db1 != nil {
		for k, v := range db1.GetFields() {
			mergedMap[k] = v.AsInterface()
		}
	}

	if db2 != nil {
		for k, v := range db2.GetFields() {
			val2 := v.AsInterface()
			if existing, ok := mergedMap[k]; ok {
				mergedVal, err := MergeDatabaseSpecificValues(existing, val2)
				if err != nil {
					logger.Info("Failed to merge database specific key", "key", k, "err", err)
				}
				mergedMap[k] = mergedVal
			} else {
				mergedMap[k] = val2
			}
		}
	}

	if len(mergedMap) > 0 {
		if ds, err := utility.NewStructpbFromMap(mergedMap); err == nil {
			mergedRange.DatabaseSpecific = ds
		} else {
			logger.Warn("Failed to create DatabaseSpecific for merged range: %v", err)
		}
	}

	return mergedRange, nil
}

// MergeDatabaseSpecificValues is a helper function that recursively merges two
// values from a DatabaseSpecific field. It handles lists (by appending), maps
// (by recursively merging keys), and simple strings (by creating a list if they
// differ). It returns an error if the types of the two values do not match.
func MergeDatabaseSpecificValues(val1, val2 any) (any, error) {
	switch v1 := val1.(type) {
	case []any:
		if v2, ok := val2.([]any); ok {
			return deduplicateList(append(v1, v2...)), nil
		}

		// Check if the list contains elements of the same type as val2
		if len(v1) > 0 {
			if reflect.TypeOf(v1[0]) != reflect.TypeOf(val2) {
				return nil, fmt.Errorf("mismatching types: list of %T and %T", v1[0], val2)
			}
		}

		// Append single value to list
		return deduplicateList(append(v1, val2)), nil
	case map[string]any:
		if v2, ok := val2.(map[string]any); ok {
			merged := make(map[string]any)
			for k, v := range v1 {
				merged[k] = v
			}
			for k, v := range v2 {
				if existing, ok := merged[k]; ok {
					mergedVal, err := MergeDatabaseSpecificValues(existing, v)
					if err != nil {
						return nil, err
					}
					merged[k] = mergedVal
				} else {
					merged[k] = v
				}
			}

			return merged, nil
		}

		return nil, fmt.Errorf("mismatching types: %T and %T", val1, val2)
	case string:
		if v2, ok := val2.(string); ok {
			if v1 == v2 {
				return v1, nil
			}

			return deduplicateList([]any{v1, v2}), nil
		}
		if v2, ok := val2.([]any); ok {
			if len(v2) > 0 {
				if _, isString := v2[0].(string); !isString {
					return nil, fmt.Errorf("mismatching types: string and list of %T", v2[0])
				}
			}

			return deduplicateList(append([]any{v1}, v2...)), nil
		}

		return nil, fmt.Errorf("mismatching types: %T and %T", val1, val2)
	default:
		if v2, ok := val2.([]any); ok {
			if len(v2) > 0 {
				if fmt.Sprintf("%T", val1) != fmt.Sprintf("%T", v2[0]) {
					return nil, fmt.Errorf("mismatching types: %T and list of %T", val1, v2[0])
				}
			}

			return deduplicateList(append([]any{val1}, v2...)), nil
		}
		if fmt.Sprintf("%T", val1) != fmt.Sprintf("%T", val2) {
			return nil, fmt.Errorf("mismatching types: %T and %T", val1, val2)
		}
		if val1 == val2 {
			return val1, nil
		}

		return deduplicateList([]any{val1, val2}), nil
	}
}

// deduplicateList removes duplicate comparable elements (like strings) from a list.
func deduplicateList(list []any) []any {
	var unique []any
	seen := make(map[any]bool)
	for _, item := range list {
		switch item.(type) {
		case string, int, int32, int64, float32, float64, bool:
			if !seen[item] {
				seen[item] = true
				unique = append(unique, item)
			}
		default:
			unique = append(unique, item)
		}
	}

	return unique
}

func ToRangeWithMetadata(r []*osvschema.Range, s models.VersionSource) []models.RangeWithMetadata {
	nr := make([]models.RangeWithMetadata, 0, len(r))
	for _, rng := range r {
		nr = append(nr, models.RangeWithMetadata{
			Range: rng,
			Metadata: models.Metadata{
				Source: s,
			},
		})
	}

	return nr
}

func CreateUnresolvedRanges(unresolvedRanges []models.RangeWithMetadata) *structpb.ListValue {
	if len(unresolvedRanges) == 0 {
		return nil
	}

	type key struct {
		Source string
		CPE    string
	}

	rangesByKey := make(map[key][]models.RangeWithMetadata)
	var keys []key

	for _, ur := range unresolvedRanges {
		k := key{Source: string(ur.Metadata.Source), CPE: ur.Metadata.CPE}
		if _, ok := rangesByKey[k]; !ok {
			keys = append(keys, k)
		}
		rangesByKey[k] = append(rangesByKey[k], ur)
	}

	slices.SortFunc(keys, func(a, b key) int {
		if a.Source != b.Source {
			return strings.Compare(a.Source, b.Source)
		}

		return strings.Compare(a.CPE, b.CPE)
	})

	listElements := make([]any, 0, len(keys))

	for _, k := range keys {
		ranges := rangesByKey[k]
		unresolvedRangesMap := make(map[string]any)
		var events []*osvschema.Event

		for _, ur := range ranges {
			urEvents := ur.Range.GetEvents()

			for _, e := range urEvents {
				if e.GetIntroduced() != "0" && e.GetIntroduced() != "" {
					events = append(events, e)
					continue
				}
				if e.GetLastAffected() != "" {
					events = append(events, e)
					continue
				}
				if e.GetFixed() != "" {
					events = append(events, e)
				}
			}
		}

		if k.CPE != "" {
			unresolvedRangesMap["cpe"] = k.CPE
		}
		if k.Source != "" {
			unresolvedRangesMap["source"] = k.Source
		}

		unresolvedRangesMap["extracted_events"] = events
		listElements = append(listElements, unresolvedRangesMap)
	}

	ds, err := utility.NewStructpbFromMap(map[string]any{
		"list": listElements,
	})
	if err != nil {
		logger.Warn("failed to convert unresolved ranges to structpb", "err", err)
		return nil
	}

	return ds.GetFields()["list"].GetListValue()
}

func AddFieldToDatabaseSpecific(ds *structpb.Struct, field string, value any) error {
	if ds == nil {
		return errors.New("database specific is nil")
	}
	if ds.Fields == nil {
		return errors.New("database specific fields is nil")
	}
	if ds.GetFields()[field] != nil {
		return fmt.Errorf("field %s already exists", field)
	}

	switch v := value.(type) {
	case *structpb.Value:
		ds.Fields[field] = v
	case *structpb.Struct:
		ds.Fields[field] = structpb.NewStructValue(v)
	case *structpb.ListValue:
		ds.Fields[field] = structpb.NewListValue(v)
	default:
		val, err := structpb.NewValue(v)
		if err != nil {
			return fmt.Errorf("failed to create structpb value: %w", err)
		}
		ds.Fields[field] = val
	}

	return nil
}

// ProcessRanges attempts to resolve the given ranges to commits and updates the metrics accordingly.
func ProcessRanges(ranges []models.RangeWithMetadata, repos []string, metrics *models.ConversionMetrics, cache git.RepoTagsCache, source models.VersionSource) ([]models.RangeWithMetadata, []models.RangeWithMetadata, []string) {
	if len(ranges) == 0 {
		return nil, nil, nil
	}

	r, un, sR := GitVersionsToCommits(ranges, repos, metrics, cache)
	if len(r) > 0 {
		metrics.ResolvedRangesCount += len(r)
		metrics.SetOutcome(models.Successful)
	}

	if len(un) > 0 {
		metrics.UnresolvedRangesCount += len(un)
		if len(r) == 0 {
			metrics.SetOutcome(models.NoCommitRanges)
		}
	}

	metrics.VersionSources = append(metrics.VersionSources, source)

	return r, un, sR
}

func LoadCPEDictionary(productToRepo *VPRepoCache, f string) error {
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	var tempMap VendorProductToRepoMap
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return err
	}
	productToRepo.Initialize(tempMap)

	return nil
}
