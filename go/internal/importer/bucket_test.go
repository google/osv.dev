package importer

import (
	"io"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/testutils"
)

func TestBucketSourceRecord_Open(t *testing.T) {
	mockBucket := testutils.NewMockStorage()
	_ = mockBucket.WriteObject(t.Context(), "path/to/test.json", []byte("data"), nil)

	mockRecord := bucketSourceRecord{
		bucket:     mockBucket,
		objectPath: "path/to/test.json",
	}

	reader, err := mockRecord.Open(t.Context())
	if err != nil {
		t.Fatalf("Failed to open bucket source record: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read from bucket source record: %v", err)
	}

	if string(data) != "data" {
		t.Errorf("Expected data, got %s", string(data))
	}
}

type mockCloudStorageProvider struct {
	buckets map[string]clients.CloudStorage
}

func (m *mockCloudStorageProvider) Bucket(name string) clients.CloudStorage {
	return m.buckets[name]
}

func TestHandleImportBucket(t *testing.T) {
	ctx := t.Context()

	// Set up mock bucket with a file
	mockBucket := testutils.NewMockStorage()
	_ = mockBucket.WriteObject(ctx, "a/b/valid.json", []byte(`{}`), &clients.WriteOptions{})
	time.Sleep(50 * time.Millisecond)
	lastUpdated := time.Now()
	time.Sleep(50 * time.Millisecond)
	_ = mockBucket.WriteObject(ctx, "a/b/newer.json", []byte(`{}`), &clients.WriteOptions{})
	_ = mockBucket.WriteObject(ctx, "a/b/ignored.json", []byte(`{}`), &clients.WriteOptions{})

	provider := &mockCloudStorageProvider{
		buckets: map[string]clients.CloudStorage{
			"test-bucket": mockBucket,
		},
	}

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]any),
	}

	config := Config{
		GCSProvider:     provider,
		SourceRepoStore: mockStore,
	}

	sourceRepo := &models.SourceRepository{
		Name:           "test-repo",
		Type:           models.SourceRepositoryTypeBucket,
		Extension:      ".json",
		IgnorePatterns: []string{".*ignored.*"},
		Bucket: &models.SourceRepoBucket{
			Name:        "test-bucket",
			Path:        "a/b/",
			LastUpdated: &lastUpdated,
		},
	}

	ch := make(chan WorkItem, 10)

	err := handleImportBucket(ctx, ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportBucket unexpected error: %v", err)
	}

	close(ch)
	records := make([]bucketSourceRecord, 0, 10)
	for r := range ch {
		records = append(records, r.SourceRecord.(bucketSourceRecord))
	}

	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	if records[0].objectPath != "a/b/newer.json" {
		t.Errorf("Expected newer.json, got %s", records[0].objectPath)
	}
}
