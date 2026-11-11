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

func TestNewLinterStore(t *testing.T) {
	t.Parallel()

	s := gcs.NewLinterStore(nil, "")
	if s == nil {
		t.Fatal("expected non-nil LinterStore")
	}

	sWithPrefix := gcs.NewLinterStore(nil, "custom-prefix")
	if sWithPrefix == nil {
		t.Fatal("expected non-nil LinterStore")
	}
}

func TestGetFindings_InvalidSource(t *testing.T) {
	t.Parallel()

	s := gcs.NewLinterStore(nil, "")
	invalidSources := []string{"", ".", "../etc/passwd", "a/b", "..", "/root"}

	for _, src := range invalidSources {
		_, err := s.GetFindings(context.Background(), src)
		if !errors.Is(err, models.ErrNotFound) {
			t.Errorf("expected ErrNotFound for source %q, got %v", src, err)
		}
	}
}

func TestParseLinterResultObjectName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		prefix string
		name   string
		want   string
		wantOK bool
	}{
		{"linter-result/", "linter-result/ghsa/result.json", "ghsa", true},
		{"linter-result/", "linter-result/cve-osv/result.json", "cve-osv", true},
		{"linter-result/", "linter-result/result.json", "", false},
		{"linter-result/", "linter-result/ghsa/sub/result.json", "", false},
		{"linter-result/", "linter-result/ghsa/other.json", "", false},
		{"linter-result/", "other-prefix/ghsa/result.json", "", false},
		{"linter-result/", "linter-result/../result.json", "", false},
		{"linter-result/", "linter-result/./result.json", "", false},
		{"linter-result/", "linter-result//result.json", "", false},
	}

	for _, tc := range tests {
		got, ok := gcs.ParseLinterResultObjectName(tc.prefix, tc.name)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("ParseLinterResultObjectName(%q, %q) = (%q, %v), want (%q, %v)",
				tc.prefix, tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestLinterStore_ListSourceInfos_GCS(t *testing.T) {
	t.Parallel()

	t.Run("lists matching result.json objects sorted by source", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/b/test-bucket/o" {
				t.Errorf("unexpected path %q", r.URL.Path)
				http.NotFound(w, r)

				return
			}
			if gotPrefix := r.URL.Query().Get("prefix"); gotPrefix != "linter-result/" {
				t.Errorf("got prefix %q, want %q", gotPrefix, "linter-result/")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"kind": "storage#objects",
				"items": [
					{"name": "linter-result/ghsa/result.json", "updated": "2026-02-01T10:00:00Z", "generation": "300"},
					{"name": "linter-result/root.json", "updated": "2026-02-01T09:00:00Z", "generation": "100"},
					{"name": "linter-result/ghsa/sub/result.json", "updated": "2026-02-01T09:00:00Z", "generation": "101"},
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
			{
				Source:     "cve-osv",
				Updated:    time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC),
				Generation: 200,
			},
			{
				Source:     "ghsa",
				Updated:    time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC),
				Generation: 300,
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ListSourceInfos() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("propagates non-retryable GCS error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)

		client, err := storage.NewClient(t.Context(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("storage.NewClient() error: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })

		store := gcs.NewLinterStore(client.Bucket("test-bucket"), "")
		if _, err := store.ListSourceInfos(t.Context()); err == nil {
			t.Fatal("expected error on GCS 403 response, got nil")
		}
	})
}
