// Package osvutil provides utilities for working with OSV data and schema structures.
package osvutil

import (
	"slices"
	"strings"

	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type EventType int

const (
	Introduced EventType = iota
	LastAffected
	Fixed
	Limit
)

func (e EventType) String() string {
	switch e {
	case Introduced:
		return "introduced"
	case LastAffected:
		return "last_affected"
	case Fixed:
		return "fixed"
	case Limit:
		return "limit"
	}

	return ""
}

type Event struct {
	Type    EventType
	Version string
}

// FromSchemaEvent consolidates the schema-to-internal conversion.
func FromSchemaEvent(e *osvschema.Event) Event {
	switch {
	case e.GetIntroduced() != "":
		return Event{Type: Introduced, Version: e.GetIntroduced()}
	case e.GetLastAffected() != "":
		return Event{Type: LastAffected, Version: e.GetLastAffected()}
	case e.GetFixed() != "":
		return Event{Type: Fixed, Version: e.GetFixed()}
	case e.GetLimit() != "":
		return Event{Type: Limit, Version: e.GetLimit()}
	}

	return Event{}
}

// SortEvents sorts a slice of Events chronologically using the Ecosystem's parse/compare rules.
func SortEvents(e ecosystem.Ecosystem, events []Event) error {
	var sortErr error

	slices.SortFunc(events, func(a, b Event) int {
		pa, errA := e.Parse(a.Version)
		pb, errB := e.Parse(b.Version)

		// Fallback to string comparison if unparsable
		if errA != nil || errB != nil {
			if errA != nil {
				sortErr = errA
			} else {
				sortErr = errB
			}
			if a.Version != b.Version {
				return strings.Compare(a.Version, b.Version)
			}

			return int(a.Type - b.Type)
		}

		res, errC := pa.Compare(pb)
		if errC != nil {
			sortErr = errC // Track that an ecosystem comparison failed
			if a.Version != b.Version {
				return strings.Compare(a.Version, b.Version)
			}

			return int(a.Type - b.Type)
		}

		if res != 0 {
			return res
		}

		// If versions are identical, sort by event type (introduced -> last_affected -> fixed -> limit)
		return int(a.Type - b.Type)
	})

	return sortErr
}
