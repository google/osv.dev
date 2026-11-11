package models

import (
	"context"
	"time"
)

// LinterSourceInfo describes a source repository's linter findings object and its version metadata.
type LinterSourceInfo struct {
	Source     string
	Updated    time.Time
	Generation int64
}

// LinterStore defines the interface for accessing linter findings from storage.
type LinterStore interface {
	// ListSources returns the list of source repository names that have linter results.
	ListSources(ctx context.Context) ([]string, error)

	// ListSourceInfos returns metadata for each source repository's linter result object.
	ListSourceInfos(ctx context.Context) ([]LinterSourceInfo, error)

	// GetFindings returns the raw JSON findings for a specific source repository.
	GetFindings(ctx context.Context, source string) ([]byte, error)
}

// UnimplementedLinterStore provides a default unimplemented stub for LinterStore.
type UnimplementedLinterStore struct{}

var _ LinterStore = UnimplementedLinterStore{}

func (UnimplementedLinterStore) ListSources(_ context.Context) ([]string, error) {
	panic("not implemented")
}

func (UnimplementedLinterStore) ListSourceInfos(_ context.Context) ([]LinterSourceInfo, error) {
	panic("not implemented")
}

func (UnimplementedLinterStore) GetFindings(_ context.Context, _ string) ([]byte, error) {
	panic("not implemented")
}
