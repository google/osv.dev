package models

import "context"

// LinterStore defines the interface for accessing linter findings from storage.
type LinterStore interface {
	// ListSources returns the list of source repository names that have linter results.
	ListSources(ctx context.Context) ([]string, error)

	// GetFindings returns the raw JSON findings for a specific source repository.
	GetFindings(ctx context.Context, source string) ([]byte, error)
}

// UnimplementedLinterStore provides a default unimplemented stub for LinterStore.
type UnimplementedLinterStore struct{}

var _ LinterStore = UnimplementedLinterStore{}

func (UnimplementedLinterStore) ListSources(_ context.Context) ([]string, error) {
	panic("not implemented")
}

func (UnimplementedLinterStore) GetFindings(_ context.Context, _ string) ([]byte, error) {
	panic("not implemented")
}
