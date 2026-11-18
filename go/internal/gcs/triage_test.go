package gcs_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/gcs"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/api/option"
)

func TestNewTriageStore(t *testing.T) {
	t.Parallel()

	s := gcs.NewTriageStore(nil)
	if s == nil {
		t.Fatal("expected non-nil TriageStore")
	}
}

func TestTriageStore_GetFile_InvalidArgument(t *testing.T) {
	t.Parallel()

	s := gcs.NewTriageStore(nil)

	tests := []struct {
		name   string
		source string
		cveID  string
	}{
		{
			name:   "invalid cve format",
			source: "cve",
			cveID:  "INVALID-CVE",
		},
		{
			name:   "invalid source",
			source: "unknown-source",
			cveID:  "CVE-2024-1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.GetFile(context.Background(), tc.source, tc.cveID)
			if !errors.Is(err, models.ErrInvalidArgument) {
				t.Errorf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestTriageStore_GetFile_GCS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		source string
		bucket string
		object string
	}{
		{"test-nvd-metrics", "osv-test-cve-osv-conversion", "metadata/nvd/metrics/CVE-2024-1234.metrics.json"},
		{"test-cve5-metrics", "osv-test-cve-osv-conversion", "metadata/cve5/metrics/CVE-2024-1234.metrics.json"},
		{"prod-nvd-metrics", "cve-osv-conversion", "metadata/nvd/metrics/CVE-2024-1234.metrics.json"},
		{"prod-cve5-metrics", "cve-osv-conversion", "metadata/cve5/metrics/CVE-2024-1234.metrics.json"},
		{"test-nvd", "osv-test-cve-osv-conversion", "nvd-osv/CVE-2024-1234.json"},
		{"test-cve5", "osv-test-cve-osv-conversion", "cve5/CVE-2024-1234.json"},
		{"test-osv", "osv-test-cve-osv-conversion", "osv-output/CVE-2024-1234.json"},
		{"prod-nvd", "cve-osv-conversion", "nvd-osv/CVE-2024-1234.json"},
		{"prod-cve5", "cve-osv-conversion", "cve5/CVE-2024-1234.json"},
		{"prod-osv", "cve-osv-conversion", "osv-output/CVE-2024-1234.json"},
	}

	objects := make(map[string]string, len(tests)*2)
	for _, tc := range tests {
		path := "/b/" + tc.bucket + "/o/" + tc.object
		objects[path] = fmt.Sprintf(`{"source":%q}`, tc.source)
		// A separate CVE keeps missing reads independent of parallel successful reads.
		objects[strings.Replace(path, "CVE-2024-1234", "CVE-2024-5678", 1)] = ""
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, ok := objects[r.URL.Path]
		if !ok {
			t.Errorf("unexpected GCS path %q", r.URL.Path)
		}
		if content == "" {
			http.NotFound(w, r)

			return
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Errorf("failed to write GCS response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := storage.NewClient(t.Context(), option.WithEndpoint(server.URL), option.WithoutAuthentication(), storage.WithJSONReads())
	if err != nil {
		t.Fatalf("failed to create storage client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close storage client: %v", err)
		}
	})
	store := gcs.NewTriageStore(client)

	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			t.Parallel()

			for _, missing := range []bool{false, true} {
				name := "found"
				cveID := "cve-2024-1234"
				if missing {
					name = "missing"
					cveID = "cve-2024-5678"
				}

				t.Run(name, func(t *testing.T) {
					t.Parallel()

					data, err := store.GetFile(t.Context(), tc.source, cveID)
					if missing {
						if !errors.Is(err, models.ErrNotFound) {
							t.Errorf("expected ErrNotFound, got %v", err)
						}

						return
					}
					if err != nil {
						t.Fatalf("GetFile failed: %v", err)
					}
					content := fmt.Sprintf(`{"source":%q}`, tc.source)
					if string(data) != content {
						t.Errorf("GetFile returned %q, want %q", data, content)
					}
				})
			}
		})
	}
}
