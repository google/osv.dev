// Package models contains the domain types for the OSV database.
package models

import (
	"context"
	"time"
)

type ImportFindings int

const (
	ImportFindingsUnknown         ImportFindings = -1
	ImportFindingsNone            ImportFindings = 0
	ImportFindingsDeleted         ImportFindings = 1
	ImportFindingsInvalidJSON     ImportFindings = 2
	ImportFindingsInvalidPackage  ImportFindings = 3
	ImportFindingsInvalidPURL     ImportFindings = 4
	ImportFindingsInvalidVersion  ImportFindings = 5
	ImportFindingsInvalidCommit   ImportFindings = 6
	ImportFindingsInvalidRange    ImportFindings = 7
	ImportFindingsInvalidRecord   ImportFindings = 8
	ImportFindingsInvalidAliases  ImportFindings = 9
	ImportFindingsInvalidUpstream ImportFindings = 10
	ImportFindingsInvalidRelated  ImportFindings = 11
	ImportFindingsBadAliasedCVE   ImportFindings = 12
)

type ImportFinding struct {
	BugID       string
	Source      string
	Findings    []ImportFindings
	FirstSeen   time.Time
	LastAttempt time.Time
}

type ImportFindingsStore interface {
	// Clear deletes all entries from the store for a given vulnerability.
	Clear(ctx context.Context, id string) error

	// ListIDs returns all existing finding IDs (bug IDs) currently stored.
	ListIDs(ctx context.Context) ([]string, error)

	// GetMulti retrieves multiple ImportFindings by bug ID.
	// For any ID not found, the corresponding element in the returned slice is nil.
	GetMulti(ctx context.Context, bugIDs []string) ([]*ImportFinding, error)

	// PutMulti creates or updates multiple ImportFindings.
	PutMulti(ctx context.Context, findings []*ImportFinding) error

	// DeleteMulti deletes multiple ImportFindings by bug ID.
	DeleteMulti(ctx context.Context, bugIDs []string) error

	// UploadResult uploads the JSON results for a given source to GCS.
	UploadResult(ctx context.Context, source string, data []byte) error

	// ListResultSources lists all sources that have linter results in the GCS bucket.
	ListResultSources(ctx context.Context) ([]string, error)

	// DeleteResult deletes the linter results for a given source in the GCS bucket.
	DeleteResult(ctx context.Context, source string) error

	// ListAllFromSource lists all import findings for a given source.
	ListAllFromSource(ctx context.Context, source string) ([]*ImportFinding, error)
}
