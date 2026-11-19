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

package worker

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func scrapeMetricsText(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read /metrics body: %v", err)
	}

	return string(body)
}

func TestLogTaskLatencyRecordsImporterLag(t *testing.T) {
	const (
		defaultSource  = "test-default-source"
		reimportSource = "test-reimport-source"
		skewSource     = "test-clock-skew-source"
	)

	received := time.Now().Add(-3 * time.Second)
	logTaskLatency(t.Context(), Task{
		SourceID:     defaultSource,
		PathInSource: "VULN-1.json",
		ReceivedTime: &received,
	}, "default")

	// Reimport pool tasks must not be recorded into live ingestion latency.
	logTaskLatency(t.Context(), Task{
		SourceID:     reimportSource,
		PathInSource: "VULN-2.json",
		ReceivedTime: &received,
	}, "reimport")

	// Future ReceivedTime (cross-pod clock skew) should clamp to 0 without negative sum.
	future := time.Now().Add(5 * time.Second)
	logTaskLatency(t.Context(), Task{
		SourceID:     skewSource,
		PathInSource: "VULN-3.json",
		ReceivedTime: &future,
	}, "default")

	metricsOut := scrapeMetricsText(t)
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_count{source="test-default-source"} 1`) {
		t.Errorf("expected default source observation to be recorded, got:\n%s", metricsOut)
	}
	if strings.Contains(metricsOut, `source="test-reimport-source"`) {
		t.Errorf("expected reimport pool task not to be recorded, got:\n%s", metricsOut)
	}
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_bucket{source="test-clock-skew-source",le="1"} 1`) {
		t.Errorf("expected clock-skewed observation to be clamped into <=1s bucket, got:\n%s", metricsOut)
	}
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_sum{source="test-clock-skew-source"} 0`) {
		t.Errorf("expected clock-skewed observation sum to clamp to 0, got:\n%s", metricsOut)
	}
}
