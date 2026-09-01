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
	metrics.RecordTaskProcessed("success", "github-advisories")
	metrics.RecordTaskProcessed("error", "nvd")
	metrics.RecordTaskDuration("success", "github-advisories", 0.42)
	metrics.RecordPipelinePublishedToAvailable("github-advisories", 120.0)
	metrics.SetDatasetTotalVulnerabilities("npm", "github-advisories", 5000)

	// Scrape metrics handler
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
		`osv_worker_tasks_processed_total{source="github-advisories",status="success"}`,
		`osv_worker_tasks_processed_total{source="nvd",status="error"}`,
		`osv_worker_task_duration_seconds_bucket{source="github-advisories",status="success"`,
		`osv_pipeline_published_to_available_seconds_bucket{source="github-advisories"`,
		`osv_dataset_total_vulnerabilities{ecosystem="npm",source="github-advisories"} 5000`,
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

	srv := metrics.NewServer("127.0.0.1:0") // system assigns free port
	srv.Start(ctx)

	// Test healthz handler directly
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srvHandler := metrics.NewServer(":0")
	srvHandler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 from healthz, got %d", rec.Code)
	}

	// Sleep briefly for server startup
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}
