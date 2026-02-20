package importer

import (
	"bytes"
	"context"
	"io"
	"iter"

	"github.com/google/osv.dev/go/internal/models"
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
