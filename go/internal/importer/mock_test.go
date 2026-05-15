package importer

import (
	"bytes"
	"context"
	"io"
	"iter"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type mockSourceRepositoryStore struct {
	updates map[string]any
}

func (m *mockSourceRepositoryStore) All(_ context.Context) iter.Seq2[*models.SourceRepository, error] {
	// not used for now
	return nil
}

func (m *mockSourceRepositoryStore) Get(_ context.Context, _ string) (*models.SourceRepository, error) {
	// not used for now
	return &models.SourceRepository{}, nil
}

func (m *mockSourceRepositoryStore) Update(_ context.Context, name string, repo *models.SourceRepository) error {
	m.updates[name] = repo
	return nil
}

type mockVulnerabilityStore struct {
	Entries map[string][]*models.VulnSourceRef
	RawMods map[string]time.Time
}

func (m *mockVulnerabilityStore) ListBySource(_ context.Context, source string, _ bool) iter.Seq2[*models.VulnSourceRef, error] {
	return func(yield func(*models.VulnSourceRef, error) bool) {
		entries := m.Entries[source]
		for _, e := range entries {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func (m *mockVulnerabilityStore) GetSourceModified(_ context.Context, vuln string) (time.Time, error) {
	if mod, ok := m.RawMods[vuln]; ok {
		return mod, nil
	}

	return time.Time{}, models.ErrNotFound
}

func (m *mockVulnerabilityStore) Get(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
	panic("not implemented")
}

func (m *mockVulnerabilityStore) GetWithMetadata(_ context.Context, _ string) (*osvschema.Vulnerability, *models.VulnSourceRef, error) {
	panic("not implemented")
}

func (m *mockVulnerabilityStore) Write(_ context.Context, _ models.WriteRequest) error {
	panic("not implemented")
}

type mockSourceRecord struct {
	DataToRead []byte
	ReadError  error
}

func (m mockSourceRecord) Open(_ context.Context) (io.ReadCloser, error) {
	if m.ReadError != nil {
		return nil, m.ReadError
	}

	return io.NopCloser(bytes.NewReader(m.DataToRead)), nil
}
