package cvelist2osv

import (
	"fmt"
	"sort"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
			// This effectively groups ranges with no introduced event together, provided
			// they share the same type and repo.
			key := groupKey{
				RangeType:  r.GetType(),
				Repo:       r.GetRepo(),
				Introduced: introduced,
			}

			if _, exists := groups[key]; !exists {
				groups[key] = &osvschema.Range{
					Type:             r.GetType(),
					Repo:             r.GetRepo(),
					Events:           []*osvschema.Event{},
					DatabaseSpecific: r.GetDatabaseSpecific(),
				}
				order = append(order, key)
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
