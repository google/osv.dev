package gcs_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/gcs"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/api/option"
)

func TestGetFindings_InvalidSource(t *testing.T) {
	t.Parallel()

	s := gcs.NewLinterStore(nil, "")
	for _, src := range []string{"", ".", "../etc/passwd", "a/b", "..", "/root"} {
		if _, err := s.GetFindings(context.Background(), src); !errors.Is(err, models.ErrNotFound) {
			t.Errorf("expected ErrNotFound for source %q, got %v", src, err)
		}
	}
}

func TestListSourceInfos(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotPrefix := r.URL.Query().Get("prefix"); gotPrefix != "linter-result/" {
			t.Errorf("got prefix %q, want linter-result/", gotPrefix)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"kind": "storage#objects",
			"items": [
				{"name": "linter-result/ghsa/result.json", "updated": "2026-02-01T10:00:00Z", "generation": "300"},
				{"name": "linter-result/root.json", "updated": "2026-02-01T09:00:00Z", "generation": "100"},
				{"name": "linter-result/ghsa/sub/result.json", "updated": "2026-02-01T09:00:00Z", "generation": "101"},
				{"name": "linter-result/../result.json", "updated": "2026-02-01T09:00:00Z", "generation": "102"},
				{"name": "linter-result/cve-osv/result.json", "updated": "2026-02-01T08:00:00Z", "generation": "200"}
			]
		}`))
	}))
	t.Cleanup(srv.Close)

	client, err := storage.NewClient(t.Context(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	store := gcs.NewLinterStore(client.Bucket("test-bucket"), "linter-result")
	got, err := store.ListSourceInfos(t.Context())
	if err != nil {
		t.Fatalf("ListSourceInfos() error: %v", err)
	}

	want := []models.LinterSourceInfo{
		{Source: "cve-osv", Updated: time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC), Generation: 200},
		{Source: "ghsa", Updated: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Generation: 300},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ListSourceInfos() mismatch (-want +got):\n%s", diff)
	}
}
