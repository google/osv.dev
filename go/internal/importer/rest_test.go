package importer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
)

type trackingReadCloser struct {
	io.Reader

	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

func TestRestSourceRecord_OpenClosesBodyOnHTTPError(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader("error")}
	record := restSourceRecord{
		cl: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 Internal Server Error",
				Body:       body,
			}, nil
		})},
		urlBase: "https://example.com",
		urlPath: "/test",
	}

	if _, err := record.Open(t.Context()); err == nil {
		t.Fatal("Open succeeded, want HTTP error")
	}
	if !body.closed {
		t.Error("response body was not closed")
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

		jsonResp := `[
			{"id": "CVE-NEWER", "modified": "2023-01-02T00:00:00Z"},
			{"id": "CVE-LOOKBACK", "modified": "2022-12-31T18:00:00Z"},
			{"id": "CVE-CUTOFF", "modified": "2022-12-31T12:00:00Z"},
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

	// Ensure that Last-Modified logic allows the fetching (and is later than maxModified)
	lastModifiedHeader = "Mon, 02 Jan 2023 12:00:00 GMT"
	err := handleImportREST(ctx, ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportREST failed: %v", err)
	}
	close(ch)

	items := make([]WorkItem, 0, 10)
	for r := range ch {
		items = append(items, r)
	}

	// Expect CVE-NEWER and CVE-LOOKBACK (within 12h lookback window before lastUpdated);
	// CVE-CUTOFF and CVE-OLDER are <= lastUpdated - 12h, and IGNORE-ME matches ignore pattern.
	if len(items) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(items))
	}

	if items[0].SourceRecord.(restSourceRecord).urlPath != "CVE-NEWER.json" || items[0].KnownID != "CVE-NEWER" {
		t.Errorf("Unexpected item[0]: path=%s knownID=%s", items[0].SourcePath, items[0].KnownID)
	}
	if items[1].SourceRecord.(restSourceRecord).urlPath != "CVE-LOOKBACK.json" || items[1].KnownID != "CVE-LOOKBACK" {
		t.Errorf("Unexpected item[1]: path=%s knownID=%s", items[1].SourcePath, items[1].KnownID)
	}

	wantLastUpdated := time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC)
	if sourceRepo.REST.LastUpdated == nil || !sourceRepo.REST.LastUpdated.Equal(wantLastUpdated) {
		t.Errorf("LastUpdated = %v, want %v", sourceRepo.REST.LastUpdated, wantLastUpdated)
	}
	wantHTTPLastModified := time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)
	if sourceRepo.REST.HTTPLastModified == nil || !sourceRepo.REST.HTTPLastModified.Equal(wantHTTPLastModified) {
		t.Errorf("HTTPLastModified = %v, want %v", sourceRepo.REST.HTTPLastModified, wantHTTPLastModified)
	}
}

func TestHandleImportREST_HEAD_NoChanges(t *testing.T) {
	ctx := t.Context()
	// Simulate the common case where index upload Last-Modified (12:00) is newer than
	// the latest advisory modified timestamp stored in LastUpdated (00:00).
	lastUpdated := time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC)
	httpLastModified := time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2023 12:00:00 GMT")
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
			URL:              ts.URL,
			LastUpdated:      &lastUpdated,
			HTTPLastModified: &httpLastModified,
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleImportREST(ctx, ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}
