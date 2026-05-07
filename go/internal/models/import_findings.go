// Package models contains the domain types for the OSV database.
package models

import (
	"context"
)

type ImportFindingsStore interface {
	// Clear deletes all entries from the store for a given vulnerability.
	Clear(ctx context.Context, id string) error
}
