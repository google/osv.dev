package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMetricsRecording(t *testing.T) {
	metrics.RecordTaskProcessed(metrics.TaskStatusSuccess)
	metrics.RecordWorkerTask(metrics.TaskStatusError, metrics.TaskActionUpdate, "default")
	metrics.RecordWorkerLatency(250 * time.Millisecond)
	metrics.RecordWorkerFailedTask(metrics.WorkerErrorEnrich, true)
	metrics.RecordUpstreamWithdrawal("ghsa")
	metrics.RecordSourceRecordDiscovered("ghsa", time.Unix(1700000000, 0))
	metrics.RecordRecovererTask("gcs_missing", metrics.TaskStatusSuccess)
	metrics.RecordGitterCommitsScanned(42)
	metrics.RecordGitterDataError(metrics.GitterErrorBadHash)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	bodyStr := string(body)

	expectedStrings := []string{
		`osv_worker_tasks_processed_total{action="unknown",status="success",work_pool="unknown"}`,
		`osv_worker_tasks_processed_total{action="update",status="error",work_pool="default"}`,
		`osv_worker_record_latency_seconds_count`,
		`osv_worker_failed_tasks_total{error_type="enrich_error",recoverable="true"}`,
		`osv_deleter_upstream_withdrawals_total{source="ghsa"}`,
		`osv_importer_records_discovered_total{source="ghsa"}`,
		`osv_importer_last_new_record_timestamp_seconds{source="ghsa"}`,
		`osv_recoverer_processed_records_total{reason="gcs_missing",status="success"}`,
		`osv_gitter_commits_scanned_total`,
		`osv_gitter_data_errors_total{error_type="bad_hash"}`,
	}

	for _, exp := range expectedStrings {
		if !strings.Contains(bodyStr, exp) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", exp, bodyStr)
		}
	}
}

func TestMetricsServerLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := metrics.NewServer("127.0.0.1:0")
	srv.Start(ctx)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 from healthz, got %d", rec.Code)
	}

	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}
