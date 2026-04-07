package conversion

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// GroupAffectedRanges groups ranges that share the same introduced value, type, and repo.
// This is because having multiple ranges with the same introduced value would act like an
// OR condition, rather than AND.
// This function modifies in-place
func GroupAffectedRanges(affected []*osvschema.Affected) {
	for _, aff := range affected {
		if len(aff.GetRanges()) <= 1 {
			continue
		}

		var rwms []models.RangeWithMetadata
		for _, r := range aff.GetRanges() {
			rwms = append(rwms, models.RangeWithMetadata{Range: r})
		}
		grouped := GroupRanges(rwms)
		var out []*osvschema.Range
		for _, rwm := range grouped {
			out = append(out, rwm.Range)
		}
		aff.Ranges = out
	}
}

func GroupRanges(ranges []models.RangeWithMetadata) []models.RangeWithMetadata {
	// Key for grouping: Type + Repo + Introduced Value
	type groupKey struct {
		RangeType  osvschema.Range_Type
		Repo       string
		Introduced string
	}

	groups := make(map[groupKey]models.RangeWithMetadata)
	var order []groupKey // To maintain deterministic order of first appearance

	for _, rwm := range ranges {
		r := rwm.Range
		// Find the introduced event
		var introduced string
		var introducedCount int
		for _, e := range r.GetEvents() {
			if e.GetIntroduced() != "" {
				introduced = e.GetIntroduced()
				introducedCount++
			}
		}

		if introducedCount > 1 {
			logger.Error("Multiple 'introduced' events found in a single range", slog.Any("range", r))
		}

		// If no introduced event is found, we use an empty string as the introduced value.
		key := groupKey{
			RangeType:  r.GetType(),
			Repo:       r.GetRepo(),
			Introduced: introduced,
		}

		if _, exists := groups[key]; !exists {
			// Initialize with a deep copy of the first range found for this group
			// We need to be careful about DatabaseSpecific.
			// We want to keep the "extracted_events" from this first range.
			groups[key] = models.RangeWithMetadata{
				Range: &osvschema.Range{
					Type:             r.GetType(),
					Repo:             r.GetRepo(),
					Events:           []*osvschema.Event{},
					DatabaseSpecific: r.GetDatabaseSpecific(), // Start with this one's DS
				},
				Metadata: rwm.Metadata,
			}
			order = append(order, key)
		} else {
			// Merge DatabaseSpecific
			mergeDatabaseSpecific(groups[key].Range, r.GetDatabaseSpecific())
		}

		// Add all events to the group. Deduplication happens later in cleanEvents.
		groups[key].Range.Events = append(groups[key].Range.Events, r.GetEvents()...)
	}

	// Reconstruct ranges from groups
	newRanges := make([]models.RangeWithMetadata, 0, len(order))
	for _, key := range order {
		rwm := groups[key]
		rwm.Range.Events = cleanEvents(rwm.Range.GetEvents())
		newRanges = append(newRanges, rwm)
	}

	return newRanges
}

// mergeDatabaseSpecific merges the source DatabaseSpecific into the target DatabaseSpecific.
// It uses MergeDatabaseSpecificValues for all fields except "extracted_events", which is handled
// by mergeDatabaseSpecificExtractedEvents for deduplication.
func mergeDatabaseSpecific(target *osvschema.Range, source *structpb.Struct) {
	if source == nil {
		return
	}

	if target.GetDatabaseSpecific() == nil {
		var err error
		target.DatabaseSpecific, err = structpb.NewStruct(nil)
		if err != nil {
			logger.Fatal("Failed to create DatabaseSpecific", slog.Any("error", err))
		}
	}

	targetFields := target.GetDatabaseSpecific().GetFields()
	if targetFields == nil {
		targetFields = make(map[string]*structpb.Value)
		target.DatabaseSpecific.Fields = targetFields
	}

	for k, v := range source.GetFields() {
		if k == "extracted_events" {
			continue // Handled separately
		}
		val2 := v.AsInterface()
		if existing, ok := targetFields[k]; ok {
			mergedVal, err := MergeDatabaseSpecificValues(existing.AsInterface(), val2)
			if err != nil {
				logger.Info("Failed to merge database specific key", "key", k, "err", err)
			}
			if newVal, err := structpb.NewValue(mergedVal); err == nil {
				targetFields[k] = newVal
			} else {
				logger.Warn("Failed to create structpb.Value for merged key", "key", k, "err", err)
			}
		} else {
			targetFields[k] = v
		}
	}

	mergeDatabaseSpecificExtractedEvents(target, source)
}

// mergeDatabaseSpecificExtractedEvents merges the "extracted_events" field from the source DatabaseSpecific
// into the target DatabaseSpecific.
//
// Examples:
//  1. Target: nil, Source: {"extracted_events": ["v1", "v2"]}
//     Result: Target becomes {"extracted_events": ["v1", "v2"]}
//  2. Target: {}, Source: {"extracted_events": ["v1", "v2"]}
//     Result: Target becomes {"extracted_events": ["v1", "v2"]}
//  3. Target: {"extracted_events": ["v1", "v3"]}, Source: {"extracted_events": ["v1", "v2"]}
//     Result: Target becomes {"extracted_events": ["v1", "v3", "v2"]} (order might vary for new additions, but existing order is preserved)
//  4. Target: {"other": "data"}, Source: {"extracted_events": ["v1", "v2"]}
//     Result: Target becomes {"other": "data", "extracted_events": ["v1", "v2"]}
//  5. Target: {"extracted_events": ["v1", "v2"]}, Source: nil
//     Result: Target remains {"extracted_events": ["v1", "v2"]}
func mergeDatabaseSpecificExtractedEvents(target *osvschema.Range, source *structpb.Struct) {
	if source == nil {
		return
	}
	sourceVersions := source.GetFields()["extracted_events"]
	if sourceVersions == nil {
		return
	}

	if target.GetDatabaseSpecific() == nil {
		var err error
		target.DatabaseSpecific, err = structpb.NewStruct(nil)
		if err != nil {
			logger.Fatal("Failed to create DatabaseSpecific", slog.Any("error", err))
		}
	}

	targetFields := target.GetDatabaseSpecific().GetFields()
	if targetFields == nil {
		targetFields = make(map[string]*structpb.Value)
		target.DatabaseSpecific.Fields = targetFields
	}

	targetVersions := targetFields["extracted_events"]
	if targetVersions == nil {
		targetFields["extracted_events"] = sourceVersions
		return
	}

	// Both have extracted events, merge them
	// Assuming extracted_events is a ListValue
	if targetVersions.GetListValue() != nil && sourceVersions.GetListValue() != nil {
		// Append source events to target events
		targetVersions.GetListValue().Values = append(targetVersions.GetListValue().GetValues(), sourceVersions.GetListValue().GetValues()...)

		// Deduplicate events
		uniqueVersions := make([]*structpb.Value, 0, len(targetVersions.GetListValue().GetValues()))
		seenVersions := make(map[string]bool)

		for _, v := range targetVersions.GetListValue().GetValues() {
			// Serialize to string for comparison
			// This might be expensive but robust for structpb.Value
			b, _ := protojson.Marshal(v)
			key := string(b)
			if seenVersions[key] {
				continue
			}
			seenVersions[key] = true
			uniqueVersions = append(uniqueVersions, v)
		}
		targetVersions.GetListValue().Values = uniqueVersions
	}
}

// cleanEvents deduplicates events and ensures there is only one Introduced event per group.
func cleanEvents(events []*osvschema.Event) []*osvschema.Event {
	uniqueEvents := make([]*osvschema.Event, 0, len(events))
	seen := make(map[string]bool)

	for _, e := range events {
		// Create a unique key for the event to check for duplicates
		key := fmt.Sprintf("%v|%v|%v|%v", e.GetIntroduced(), e.GetFixed(), e.GetLimit(), e.GetLastAffected())
		if seen[key] {
			continue
		}
		seen[key] = true
		uniqueEvents = append(uniqueEvents, e)
	}

	// Sort: Introduced events come first.
	slices.SortStableFunc(uniqueEvents, func(a, b *osvschema.Event) int {
		// Introduced comes before everything else
		if a.GetIntroduced() != "" && b.GetIntroduced() == "" {
			return -1
		}
		if a.GetIntroduced() == "" && b.GetIntroduced() != "" {
			return 1
		}

		return 0
	})

	// Ensure only one Introduced event remains.
	// Since we grouped by Introduced value, all Introduced events in this group are identical.
	var finalEvents []*osvschema.Event
	introduced := ""
	for _, e := range uniqueEvents {
		if e.GetIntroduced() != "" {
			if introduced == "" {
				finalEvents = append(finalEvents, e)
				introduced = e.GetIntroduced()
			} else if introduced != e.GetIntroduced() {
				logger.Error("Found multiple introduced values in the same group", slog.Any("introduced", introduced), slog.Any("event", e.GetIntroduced()))
			}
		} else {
			finalEvents = append(finalEvents, e)
		}
	}

	return finalEvents
}

// MergeRangesAndCreateAffected combines resolved and unresolved ranges with commits to create an OSV Affected object.
// It merges ranges for the same repository and adds commit events to the appropriate ranges at the end.
//
// Arguments:
//   - resolvedRanges: A slice of resolved OSV ranges to be merged.
//   - commits: A slice of affected commits to be converted into events and added to ranges.
//   - successfulRepos: A slice of repository URLs that were successfully processed.
//
// FYI: this argument exists because navigating and extracting the repository information
// when it is nested inside the range is a pain, considering we don't want to use
// maps for storing information due to their non-deterministic behaviour in conjunction
// with protojson
//   - metrics: A pointer to ConversionMetrics to track the outcome and notes.
func MergeRangesAndCreateAffected(
	resolvedRanges []models.RangeWithMetadata,
	commits []models.AffectedCommit,
	successfulRepos []string,
	metrics *models.ConversionMetrics,
) []*osvschema.Affected {
	var newAffected []*osvschema.Affected
	// Combine the ranges appropriately
	if len(resolvedRanges) > 0 {
		slices.Sort(successfulRepos)
		successfulRepos = slices.Compact(successfulRepos)
		for _, repo := range successfulRepos {
			var mergedRange *osvschema.Range
			for _, vrwm := range resolvedRanges {
				vr := vrwm.Range
				if vr.GetRepo() == repo {
					if mergedRange == nil {
						mergedRange = vr
					} else {
						var err error
						mergedRange, err = MergeTwoRanges(mergedRange, vr)
						if err != nil {
							metrics.AddNote("Failed to merge ranges: %v", err)
						}
					}
				}
			}
			if len(commits) > 0 {
				for _, commit := range commits {
					if commit.Repo == repo {
						if mergedRange == nil {
							mergedRange = BuildGitVersionRange(commit.Introduced, commit.LastAffected, commit.Fixed, repo)
						} else {
							event := convertCommitToEvent(commit)
							if event != nil {
								addEventToRange(mergedRange, event)
							}
						}

						if mergedRange.GetDatabaseSpecific() == nil {
							mergedRange.DatabaseSpecific = &structpb.Struct{
								Fields: make(map[string]*structpb.Value),
							}
						}
						mergeDatabaseSpecific(mergedRange, &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"source": structpb.NewStringValue(string(models.VersionSourceRefs)),
							},
						})
					}
				}
			}
			if mergedRange != nil {
				newAffected = append(newAffected, &osvschema.Affected{
					Ranges: []*osvschema.Range{mergedRange},
				})
			}
		}
	}

	// if there are no resolved version but there are commits, we should group them by repository
	if len(resolvedRanges) == 0 && len(commits) > 0 {
		repoToRange := make(map[string]*osvschema.Range)
		var repoOrder []string

		for _, commit := range commits {
			repo := commit.Repo
			if vr, ok := repoToRange[repo]; !ok {
				vr := BuildGitVersionRange(commit.Introduced, commit.LastAffected, commit.Fixed, repo)
				vr.DatabaseSpecific = &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"source": structpb.NewStringValue(string(models.VersionSourceRefs)),
					},
				}
				repoToRange[repo] = vr
				repoOrder = append(repoOrder, repo)
				metrics.ResolvedRangesCount++
			} else {
				event := convertCommitToEvent(commit)
				if event != nil {
					addEventToRange(vr, event)
				}
			}
		}

		// Make sure that packages/repos are added deterministically.
		// doesn't use successful repos as that is more-or-less just a resolvedRanges-specific crutch
		slices.Sort(repoOrder)
		for _, repo := range repoOrder {
			newAffected = append(newAffected, &osvschema.Affected{
				Ranges: []*osvschema.Range{repoToRange[repo]},
			})
		}
	}

	return newAffected
}

// addEventToRange adds an event to a version range, avoiding duplicates.
// Introduced events are prepended to the events list, while others are appended.
//
// Arguments:
//   - versionRange: The OSV range to which the event will be added.
//   - event: The OSV event (Introduced, Fixed, or LastAffected) to add.
func addEventToRange(versionRange *osvschema.Range, event *osvschema.Event) {
	// Handle duplicate events being added
	for _, e := range versionRange.GetEvents() {
		if e.GetIntroduced() != "" && e.GetIntroduced() == event.GetIntroduced() {
			return
		}
		if e.GetFixed() != "" && e.GetFixed() == event.GetFixed() {
			return
		}
		if e.GetLastAffected() != "" && e.GetLastAffected() == event.GetLastAffected() {
			return
		}
	}
	//TODO: maybe handle if the fixed event appears as an introduced event or similar.

	if event.GetIntroduced() != "" {
		versionRange.Events = append([]*osvschema.Event{{
			Introduced: event.GetIntroduced()}}, versionRange.GetEvents()...)
	} else {
		versionRange.Events = append(versionRange.Events, event)
	}
}

// convertCommitToEvent creates an OSV Event from an AffectedCommit.
// It returns an event with the Introduced, Fixed, or LastAffected value from the commit.
func convertCommitToEvent(commit models.AffectedCommit) *osvschema.Event {
	if commit.Introduced != "" {
		return &osvschema.Event{
			Introduced: commit.Introduced,
		}
	}
	if commit.Fixed != "" {
		return &osvschema.Event{
			Fixed: commit.Fixed,
		}
	}
	if commit.LastAffected != "" {
		return &osvschema.Event{
			LastAffected: commit.LastAffected,
		}
	}

	return nil
}
