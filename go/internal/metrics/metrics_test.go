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

func TestMetricsRegistrationAndScraping(t *testing.T) {
	// Increment metrics
	metrics.WorkerTasksProcessed.WithLabelValues("update", "success", "npm", "github.com/advisories").Inc()
	metrics.WorkerRecordLatency.WithLabelValues("github.com/advisories").Observe(1.23)
	metrics.GitterDataErrors.WithLabelValues("bad_hash").Inc()
	metrics.GitterDiskUsedBytes.Set(1024 * 1024 * 1024)

	// Create test server scraping Prometheus handler
	ts := httptest.NewServer(promhttp.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to scrape /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "osv_worker_tasks_processed_total") {
		t.Errorf("expected metric osv_worker_tasks_processed_total not found in /metrics output")
	}
	if !strings.Contains(bodyStr, "osv_gitter_data_errors_total") {
		t.Errorf("expected metric osv_gitter_data_errors_total not found in /metrics output")
	}
	if !strings.Contains(bodyStr, "osv_gitter_disk_used_bytes") {
		t.Errorf("expected metric osv_gitter_disk_used_bytes not found in /metrics output")
	}
}

func TestStartServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metrics.StartServer(ctx, "19099")
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://localhost:19099/healthz")
	if err != nil {
		t.Fatalf("failed to ping /healthz on metrics server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 from /healthz, got %d", resp.StatusCode)
	}
}
