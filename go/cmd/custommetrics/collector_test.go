// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type mockSourceRepoStore struct {
	models.SourceRepositoryStore

	repos []*models.SourceRepository
}

func (m *mockSourceRepoStore) All(_ context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(yield func(*models.SourceRepository, error) bool) {
		for _, r := range m.repos {
			if !yield(r, nil) {
				return
			}
		}
	}
}

type mockJobDataStore struct {
	data map[string]any
}

func (m *mockJobDataStore) Get(_ context.Context, key string, dst any) error {
	val, ok := m.data[key]
	if !ok {
		return models.ErrNotFound
	}
	switch d := dst.(type) {
	case *[]string:
		*d = val.([]string)
	case *models.ReconcilerSummary:
		*d = val.(models.ReconcilerSummary)
	case *models.DeleterSummary:
		*d = val.(models.DeleterSummary)
	}

	return nil
}

func (m *mockJobDataStore) Set(_ context.Context, key string, val any) error {
	m.data[key] = val

	return nil
}

type mockImportFindingsStore struct {
	models.ImportFindingsStore

	findings []*models.ImportFinding
}

func (m *mockImportFindingsStore) ListAll(_ context.Context) ([]*models.ImportFinding, error) {
	return m.findings, nil
}

func TestCollectMetrics(t *testing.T) {
	ctx := context.Background()
	gcsMock := testutils.NewMockStorage()

	lastUpdated := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	sourceRepoStore := &mockSourceRepoStore{
		repos: []*models.SourceRepository{
			{
				Name:       "ghsa",
				Type:       models.SourceRepositoryTypeBucket,
				IDPrefixes: []string{"GHSA-"},
				Bucket: &models.SourceRepoBucket{
					Name:        "ghsa-bucket",
					LastUpdated: &lastUpdated,
				},
			},
			{
				Name:       "android",
				Type:       models.SourceRepositoryTypeBucket,
				IDPrefixes: []string{"A-", "ASB-A", "PUB-A"},
			},
		},
	}

	jobDataStore := &mockJobDataStore{
		data: map[string]any{
			models.JobDataRecordCheckerInvalidRecords: []string{"GHSA-1111", "GHSA-2222", "ASB-A-153358911"},
			models.JobDataReconcilerSummary: models.ReconcilerSummary{
				UpToDateCount: 100,
				MissingCount:  5,
				OutdatedCount: 3,
			},
			models.JobDataDeleterSummary: models.DeleterSummary{
				RefusedBySource: map[string]int64{"ghsa": 42},
			},
		},
	}

	importFindingsStore := &mockImportFindingsStore{
		findings: []*models.ImportFinding{
			{
				BugID:    "GHSA-1111",
				Source:   "ghsa",
				Findings: []models.ImportFindings{models.ImportFindingsInvalidRange, models.ImportFindingsInvalidAliases},
			},
			{
				BugID:    "ASB-A-153358911",
				Findings: []models.ImportFindings{models.ImportFindingsInvalidPackage},
			},
		},
	}

	_ = gcsMock.WriteObject(ctx, "all.zip", []byte("zip-bytes-12345"), nil)
	_ = gcsMock.WriteObject(ctx, "modified_id.csv", []byte("2026-10-15T00:00:00Z,PyPI/GHSA-1111\n2026-10-15T00:00:00Z,npm/GHSA-1111\n2026-10-15T00:00:00Z,PyPI/GHSA-2222\n"), nil)
	_ = gcsMock.WriteObject(ctx, "ecosystems.txt", []byte("PyPI\n"), nil)
	_ = gcsMock.WriteObject(ctx, "PyPI/all.zip", []byte("pypi-zip"), nil)
	_ = gcsMock.WriteObject(ctx, "PyPI/modified_id.csv", []byte("2026-10-15T00:00:00Z,GHSA-1111\n2026-10-15T00:00:00Z,GHSA-2222\n"), nil)

	collector := NewCollector(Stores{
		SourceRepo:     sourceRepoStore,
		JobData:        jobDataStore,
		ImportFindings: importFindingsStore,
		GCS:            gcsMock,
	})

	collector.CollectMetrics(ctx)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(w, req)
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatalf("Failed to read /metrics body: %v", err)
	}
	metricsText := string(body)

	wantMetrics := []string{
		`osv_importer_last_new_record_timestamp_seconds{source="ghsa"} 1.7920656e+09`,
		`osv_recordchecker_drift{type="gcs_missing_or_stale"} 3`,
		`osv_recordchecker_invalid_records{source="ghsa"} 2`,
		`osv_recordchecker_invalid_records{source="android"} 1`,
		`osv_reconciler_records_reconciled{status="missing"} 5`,
		`osv_deleter_refused_deletions{source="ghsa"} 42`,
		`osv_data_quality_findings{rule_code="RNG:001",severity="error",source="ghsa"} 1`,
		`osv_data_quality_findings{rule_code="PKG:001",severity="error",source="android"} 1`,
		`osv_dataset_total_vulnerabilities{ecosystem="all"} 2`,
		`osv_dataset_total_vulnerabilities{ecosystem="PyPI"} 2`,
		`osv_export_zip_size_bytes{ecosystem="all"} 15`,
	}
	for _, want := range wantMetrics {
		if !strings.Contains(metricsText, want) {
			t.Errorf("Expected /metrics output to contain %q, got:\n%s", want, metricsText)
		}
	}
}
