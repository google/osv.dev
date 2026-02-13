package importer

import (
	"bytes"
	"context"
	"io"
	"iter"
	"time"

	"github.com/google/osv.dev/go/internal/models"
)

type mockSourceRepositoryStore struct {
	updates map[string]interface{}
}

func (m *mockSourceRepositoryStore) All(ctx context.Context) iter.Seq2[*models.SourceRepository, error] {
	// not used for now
	return nil
}

func (m *mockSourceRepositoryStore) Get(ctx context.Context, name string) (*models.SourceRepository, error) {
	// not used for now
	return nil, nil
}

func (m *mockSourceRepositoryStore) Update(ctx context.Context, name string, repo *models.SourceRepository) error {
	m.updates[name] = repo
	return nil
}

type mockVulnerabilityStore struct {
	Entries map[string][]*models.VulnSourceRef
}

func (m *mockVulnerabilityStore) ListBySource(ctx context.Context, source string, skipWithdrawn bool) iter.Seq2[*models.VulnSourceRef, error] {
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
	MockKeyPath          string
	MockFormat           RecordFormat
	MockLastUpdated      time.Time
	MockHasUpdateTime    bool
	MockSourceRepository string
	MockSourcePath       string
	MockSendModifiedTime bool

	DataToRead       []byte
	ReadError        error
	ShouldSendUpdate bool
}

func (m mockSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	if m.ReadError != nil {
		return nil, m.ReadError
	}
	return io.NopCloser(bytes.NewReader(m.DataToRead)), nil
}

func (m mockSourceRecord) KeyPath() string {
	return m.MockKeyPath
}

func (m mockSourceRecord) Format() RecordFormat {
	return m.MockFormat
}

func (m mockSourceRecord) LastUpdated() (time.Time, bool) {
	return m.MockLastUpdated, m.MockHasUpdateTime
}

func (m mockSourceRecord) SourceRepository() string {
	return m.MockSourceRepository
}

func (m mockSourceRecord) SourcePath() string {
	return m.MockSourcePath
}

func (m mockSourceRecord) ShouldSendModifiedTime() bool {
	return m.MockSendModifiedTime
}
