package importer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/testutils"
)

func TestHandleDeleteBucket(t *testing.T) {
	ctx := t.Context()

	// Setup Mock Bucket with 1 remaining file
	mockBucket := testutils.NewMockStorage()
	_ = mockBucket.WriteObject(ctx, "a/b/still-there.json", []byte(`{}`), nil)

	provider := &mockCloudStorageStorageProvider{
		buckets: map[string]clients.CloudStorage{
			"test-bucket": mockBucket,
		},
	}

	// Setup Mock Datastore with 2 files (one missing from bucket)
	mockVulnStore := &mockVulnerabilityStore{
		Entries: map[string][]*models.VulnSourceRef{
			"test-repo": {
				{ID: "ID-1", Source: "test-repo", Path: "a/b/still-there.json"},
				{ID: "ID-2", Source: "test-repo", Path: "a/b/deleted-file.json"},
			},
		},
	}

	mockPublisher := &testutils.MockPublisher{}

	config := Config{
		GCSProvider:        provider,
		VulnerabilityStore: mockVulnStore,
		Publisher:          mockPublisher,
		DeleteThreshold:    100.0, // High threshold for test
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-repo",
		Type:      models.SourceRepositoryTypeBucket,
		Extension: ".json",
		Bucket: &models.SourceRepoBucket{
			Name: "test-bucket",
			Path: "a/b/",
		},
	}

	workCh := make(chan WorkItem, 10)
	err := handleDeleteBucket(ctx, workCh, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleDeleteBucket unexpected error: %v", err)
	}
	close(workCh)

	items := make([]WorkItem, 0, 10)
	for r := range workCh {
		items = append(items, r)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 deletion record, got %d", len(items))
	}

	if !items[0].IsDeleted {
		t.Errorf("Expected IsDeleted=true, got false")
	}
	if items[0].SourcePath != "a/b/deleted-file.json" {
		t.Errorf("Expected path a/b/deleted-file.json, got %s", items[0].SourcePath)
	}
}

func TestHandleDeleteBucket_Threshold(t *testing.T) {
	ctx := t.Context()

	// Empty bucket
	mockBucket := testutils.NewMockStorage()
	provider := &mockCloudStorageStorageProvider{
		buckets: map[string]clients.CloudStorage{
			"test-bucket": mockBucket,
		},
	}

	// Datastore has 10 entries
	entries := make([]*models.VulnSourceRef, 10)
	for i := range 10 {
		entries[i] = &models.VulnSourceRef{ID: "ID", Path: "path"}
	}
	mockVulnStore := &mockVulnerabilityStore{
		Entries: map[string][]*models.VulnSourceRef{
			"test-repo": entries,
		},
	}

	mockPublisher := &testutils.MockPublisher{}

	config := Config{
		GCSProvider:        provider,
		VulnerabilityStore: mockVulnStore,
		Publisher:          mockPublisher,
		DeleteThreshold:    10.0, // 10% threshold
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-repo",
		Type:      models.SourceRepositoryTypeBucket,
		Extension: ".json",
		Bucket: &models.SourceRepoBucket{
			Name: "test-bucket",
		},
	}

	// Should fail because 100% of records are missing from bucket
	workCh := make(chan WorkItem, 10)
	err := handleDeleteBucket(ctx, workCh, config, sourceRepo)
	if err == nil {
		t.Fatal("Expected error due to threshold, got nil")
	}
	close(workCh)

	if len(workCh) != 0 {
		t.Errorf("Expected 0 messages due to threshold refusal, got %d", len(workCh))
	}
}

func TestHandleDeleteREST(t *testing.T) {
	ctx := t.Context()

	// Mock Server returns 1 remaining ID
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`[{"id": "STILL-THERE"}]`)); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	// Datastore has 2 IDs
	mockVulnStore := &mockVulnerabilityStore{
		Entries: map[string][]*models.VulnSourceRef{
			"test-repo": {
				{ID: "STILL-THERE", Source: "test-repo", Path: "STILL-THERE.json"},
				{ID: "DELETED", Source: "test-repo", Path: "DELETED.json"},
			},
		},
	}

	mockPublisher := &testutils.MockPublisher{}

	config := Config{
		HTTPClient:         ts.Client(),
		VulnerabilityStore: mockVulnStore,
		Publisher:          mockPublisher,
		DeleteThreshold:    100.0,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-repo",
		Type:      models.SourceRepositoryTypeREST,
		Extension: ".json",
		REST: &models.SourceRepoREST{
			URL: ts.URL,
		},
	}

	workCh := make(chan WorkItem, 10)
	err := handleDeleteREST(ctx, workCh, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleDeleteREST failed: %v", err)
	}
	close(workCh)

	items := make([]WorkItem, 0, 10)
	for r := range workCh {
		items = append(items, r)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 deletion record, got %d", len(items))
	}

	if items[0].SourcePath != "DELETED.json" {
		t.Errorf("Expected path DELETED.json, got %s", items[0].SourcePath)
	}
}

type mockCloudStorageStorageProvider struct {
	buckets map[string]clients.CloudStorage
}

func (m *mockCloudStorageStorageProvider) Bucket(name string) clients.CloudStorage {
	return m.buckets[name]
}
