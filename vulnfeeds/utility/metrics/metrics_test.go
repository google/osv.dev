package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestRecordConversionMetric(t *testing.T) {
	cm := &models.ConversionMetrics{
		CVEID:                 "CVE-2026-1234",
		CNA:                   "GitHub",
		Outcome:               models.Successful,
		ResolvedRangesCount:   2,
		UnresolvedRangesCount: 0,
		VersionSources:        []models.VersionSource{models.VersionSourceAffected, models.VersionSourceGit},
	}

	metrics.RecordConversionMetric("cve5", cm)

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
	if !strings.Contains(bodyStr, "osv_cve_conversion_outcomes_total") {
		t.Errorf("expected metric osv_cve_conversion_outcomes_total not found in /metrics")
	}
	if !strings.Contains(bodyStr, "osv_cve_conversion_ranges_total") {
		t.Errorf("expected metric osv_cve_conversion_ranges_total not found in /metrics")
	}
	if !strings.Contains(bodyStr, "osv_cve_conversion_version_sources_total") {
		t.Errorf("expected metric osv_cve_conversion_version_sources_total not found in /metrics")
	}
}
