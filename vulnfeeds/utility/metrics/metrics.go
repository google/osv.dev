// Package metrics defines Prometheus metrics for CVE and vulnerability feed converters in vulnfeeds.
package metrics

import (
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ConversionOutcomesTotal tracks CVE conversion outcomes by converter, outcome, and CNA.
	ConversionOutcomesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "cve_conversion",
			Name:      "outcomes_total",
			Help:      "Total CVE conversion outcomes by converter, outcome, and CNA.",
		},
		[]string{"converter", "outcome", "cna"},
	)

	// ConversionRangesTotal tracks resolved and unresolved ranges during conversion.
	ConversionRangesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "cve_conversion",
			Name:      "ranges_total",
			Help:      "Total version and commit ranges processed by status (resolved or unresolved).",
		},
		[]string{"converter", "status"},
	)

	// ConversionVersionSourcesTotal tracks the source of extracted versions.
	ConversionVersionSourcesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "cve_conversion",
			Name:      "version_sources_total",
			Help:      "Total version sources extracted during conversion (AFFECTED_FIELD, CPE_RANGE, etc.).",
		},
		[]string{"converter", "source_type"},
	)

	// ConversionDurationSeconds tracks the duration of conversion runs.
	ConversionDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "cve_conversion",
			Name:      "duration_seconds",
			Help:      "Duration of CVE conversion runs in seconds.",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		},
		[]string{"converter"},
	)

	// ConversionGCSBlockedTotal tracks the number of times the GCS upload pool was blocked.
	ConversionGCSBlockedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "cve_conversion",
			Name:      "gcs_blocked_total",
			Help:      "Number of times GCS upload pool was blocked due to concurrency.",
		},
		[]string{"converter"},
	)
)

// RecordConversionMetric records metrics for a single converted CVE.
func RecordConversionMetric(converter string, m *models.ConversionMetrics) {
	if m == nil {
		return
	}

	cna := m.CNA
	if cna == "" {
		cna = "UNKNOWN"
	}

	outcomeStr := m.Outcome.String()
	ConversionOutcomesTotal.WithLabelValues(converter, outcomeStr, cna).Inc()

	if m.ResolvedRangesCount > 0 {
		ConversionRangesTotal.WithLabelValues(converter, "resolved").Add(float64(m.ResolvedRangesCount))
	}
	if m.UnresolvedRangesCount > 0 {
		ConversionRangesTotal.WithLabelValues(converter, "unresolved").Add(float64(m.UnresolvedRangesCount))
	}

	for _, src := range m.VersionSources {
		ConversionVersionSourcesTotal.WithLabelValues(converter, string(src)).Inc()
	}
}
