package importer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
)

func TestRestSourceRecord_Open(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("data")); err != nil {
			t.Fatalf("Failed to write: %v", err)
		}
	}))
	defer ts.Close()

	record := restSourceRecord{
		cl:      ts.Client(),
		urlBase: ts.URL,
		urlPath: "/test",
	}

	reader, err := record.Open(t.Context())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(data) != "data" {
		t.Errorf("Expected 'data', got '%s'", string(data))
	}
}

func TestHandleImportREST(t *testing.T) {
	ctx := t.Context()
	lastUpdated := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	lastModifiedHeader := "Sun, 01 Jan 2023 00:00:00 GMT" // RFC1123

	// Create a mock server that serves an array of Vulnerabilities
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", lastModifiedHeader)
			w.WriteHeader(http.StatusOK)

			return
		}

		// Return two records: one newer, one older (or ignored)
		jsonResp := `[
			{"id": "CVE-NEWER", "modified": "2023-01-02T00:00:00Z"},
			{"id": "CVE-OLDER", "modified": "2022-12-31T00:00:00Z"},
			{"id": "IGNORE-ME", "modified": "2023-01-02T00:00:00Z"}
		]`
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(jsonResp)); err != nil {
			t.Fatalf("Failed to write: %v", err)
		}
	}))
	defer ts.Close()

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]any),
	}
	config := Config{
		HTTPClient:      ts.Client(),
		SourceRepoStore: mockStore,
	}

	sourceRepo := &models.SourceRepository{
		Name:           "test-rest-repo",
		Type:           models.SourceRepositoryTypeREST,
		Extension:      ".json",
		Link:           "http://example.com/api/",
		IgnorePatterns: []string{"IGNORE-.*"},
		REST: &models.SourceRepoREST{
			URL:         ts.URL,
			LastUpdated: &lastUpdated,
		},
	}

	ch := make(chan WorkItem, 10)

	// Ensure that Last-Modified logic allows the fetching
	lastModifiedHeader = "Mon, 02 Jan 2023 00:00:00 GMT" // Newer than lastUpdated
	err := handleImportREST(ctx, ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportREST failed: %v", err)
	}
	close(ch)

	records := make([]restSourceRecord, 0, 10)
	for r := range ch {
		records = append(records, r.SourceRecord.(restSourceRecord))
	}

	// We expect 1 record: CVE-NEWER
	// (CVE-OLDER is skipped due to modified time, IGNORE-ME is skipped due to regex)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	if records[0].urlPath != "CVE-NEWER.json" {
		t.Errorf("Expected urlPath=CVE-NEWER.json, got %s", records[0].urlPath)
	}
}

func TestHandleImportREST_HEAD_NoChanges(t *testing.T) {
	ctx := t.Context()
	lastUpdated := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	// Server returns a Last-Modified older than LastUpdated
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", "Sat, 31 Dec 2022 00:00:00 GMT")
			w.WriteHeader(http.StatusOK)

			return
		}
		t.Error("GET should not be called")
	}))
	defer ts.Close()

	config := Config{
		HTTPClient: ts.Client(),
	}

	sourceRepo := &models.SourceRepository{
		Name: "test-rest-repo",
		Type: models.SourceRepositoryTypeREST,
		REST: &models.SourceRepoREST{
			URL:         ts.URL,
			LastUpdated: &lastUpdated,
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleImportREST(ctx, ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}
