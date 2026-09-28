package models

import "context"

// TriageStore defines the interface for fetching CVE conversion data and external records for triage.
type TriageStore interface {
	// GetFile retrieves the raw JSON content for a given source and CVE ID.
	GetFile(ctx context.Context, source, cveID string) ([]byte, error)
}

// UnimplementedTriageStore provides a default unimplemented stub for TriageStore.
type UnimplementedTriageStore struct{}

var _ TriageStore = UnimplementedTriageStore{}

func (UnimplementedTriageStore) GetFile(_ context.Context, _, _ string) ([]byte, error) {
	panic("not implemented")
}
