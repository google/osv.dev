package cvelist2osv

import (
	"fmt"
	"sort"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// groupAffectedRanges groups ranges that share the same introduced value, type, and repo.
// This is because having multiple ranges with the same introduced value would act like an
// OR condition, rather than AND.
func groupAffectedRanges(affected []*osvschema.Affected) {
	for _, aff := range affected {
		if len(aff.GetRanges()) <= 1 {
			continue
		}

		// Key for grouping: Type + Repo + Introduced Value
		type groupKey struct {
			RangeType  osvschema.Range_Type
			Repo       string
			Introduced string
		}

		groups := make(map[groupKey]*osvschema.Range)
		var order []groupKey // To maintain deterministic order of first appearance

		for _, r := range aff.GetRanges() {
			// Find the introduced event
			var introduced string
			for _, e := range r.GetEvents() {
				if e.GetIntroduced() != "" {
					introduced = e.GetIntroduced()
					break
				}
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
				// We want to keep the "versions" from this first range.
				groups[key] = &osvschema.Range{
					Type:             r.GetType(),
					Repo:             r.GetRepo(),
					Events:           []*osvschema.Event{},
					DatabaseSpecific: r.GetDatabaseSpecific(), // Start with this one's DS
				}
				order = append(order, key)
			} else {
				// Merge DatabaseSpecific "versions"
				mergeDatabaseSpecificVersions(groups[key], r.GetDatabaseSpecific())
			}

			// Add all events to the group. Deduplication happens later in cleanEvents.
			groups[key].Events = append(groups[key].Events, r.GetEvents()...)
		}

		// Reconstruct ranges from groups
		var newRanges []*osvschema.Range
		for _, key := range order {
			r := groups[key]
			r.Events = cleanEvents(r.GetEvents())
			newRanges = append(newRanges, r)
		}
		aff.Ranges = newRanges
	}
}

func mergeDatabaseSpecificVersions(target *osvschema.Range, source *structpb.Struct) {
	if source == nil {
		return
	}
	sourceVersions := source.GetFields()["versions"]
	if sourceVersions == nil {
		return
	}

	if target.GetDatabaseSpecific() == nil {
		target.DatabaseSpecific = &structpb.Struct{Fields: make(map[string]*structpb.Value)}
	}

	targetFields := target.GetDatabaseSpecific().GetFields()
	if targetFields == nil {
		targetFields = make(map[string]*structpb.Value)
		target.DatabaseSpecific.Fields = targetFields
	}

	targetVersions := targetFields["versions"]
	if targetVersions == nil {
		targetFields["versions"] = sourceVersions
		return
	}

	// Both have versions, merge them
	// Assuming versions is a ListValue
	if targetVersions.GetListValue() != nil && sourceVersions.GetListValue() != nil {
		// Append source versions to target versions
		targetVersions.GetListValue().Values = append(targetVersions.GetListValue().GetValues(), sourceVersions.GetListValue().GetValues()...)

		// Deduplicate versions
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
	sort.SliceStable(uniqueEvents, func(i, j int) bool {
		// Introduced comes before everything else
		if uniqueEvents[i].GetIntroduced() != "" && uniqueEvents[j].GetIntroduced() == "" {
			return true
		}
		if uniqueEvents[i].GetIntroduced() == "" && uniqueEvents[j].GetIntroduced() != "" {
			return false
		}
		// If both are introduced or both are not, keep original order (stable)
		return i < j
	})

	// Ensure only one Introduced event remains.
	// Since we grouped by Introduced value, all Introduced events in this group are identical.
	var finalEvents []*osvschema.Event
	hasIntroduced := false
	for _, e := range uniqueEvents {
		if e.GetIntroduced() != "" {
			if !hasIntroduced {
				finalEvents = append(finalEvents, e)
				hasIntroduced = true
			}
			// Skip subsequent Introduced events as they are duplicates
		} else {
			finalEvents = append(finalEvents, e)
		}
	}

	return finalEvents
}
