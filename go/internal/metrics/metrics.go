// Package metrics provides Prometheus metric definitions and exposition for OSV services.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// PipelinePublishedToAvailableSeconds tracks the end-to-end latency between
	// the upstream publish/source timestamp and when the vulnerability is saved in the OSV database.
	PipelinePublishedToAvailableSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "osv_pipeline_published_to_available_seconds",
			Help: "Seconds between upstream vulnerability publish/source timestamp and OSV database write.",
			Buckets: []float64{
				60,     // 1 min
				300,    // 5 min
				600,    // 10 min
				1800,   // 30 min
				3600,   // 1 hour
				7200,   // 2 hours (SLO threshold)
				14400,  // 4 hours
				28800,  // 8 hours
				86400,  // 24 hours
				172800, // 48 hours
				604800, // 7 days
			},
		},
		[]string{"source"},
	)

	// WorkerTasksProcessedTotal tracks the total number of ingestion/enrichment tasks processed by the worker.
	WorkerTasksProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_worker_tasks_processed_total",
			Help: "Total number of tasks processed by the worker.",
		},
		[]string{"status", "source"},
	)

	// WorkerTaskDurationSeconds tracks the duration taken by workers to process individual tasks.
	WorkerTaskDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "osv_worker_task_duration_seconds",
			Help: "Duration in seconds to process a worker task.",
			Buckets: []float64{
				0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
			},
		},
		[]string{"status", "source"},
	)

	// DatasetTotalVulnerabilities tracks the total number of vulnerabilities in the OSV dataset.
	DatasetTotalVulnerabilities = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_dataset_total_vulnerabilities",
			Help: "Total number of vulnerabilities in the OSV dataset.",
		},
		[]string{"ecosystem", "source"},
	)
)

// RecordTaskProcessed increments the task processed counter for a given status and source.
func RecordTaskProcessed(status, source string) {
	if source == "" {
		source = "unknown"
	}
	WorkerTasksProcessedTotal.WithLabelValues(status, source).Inc()
}

// RecordTaskDuration records the processing duration of a task in seconds.
func RecordTaskDuration(status, source string, durationSeconds float64) {
	if source == "" {
		source = "unknown"
	}
	WorkerTaskDurationSeconds.WithLabelValues(status, source).Observe(durationSeconds)
}

// RecordPipelinePublishedToAvailable records the end-to-end lag from publication to database write.
func RecordPipelinePublishedToAvailable(source string, durationSeconds float64) {
	if source == "" {
		source = "unknown"
	}
	PipelinePublishedToAvailableSeconds.WithLabelValues(source).Observe(durationSeconds)
}

// SetDatasetTotalVulnerabilities sets the vulnerability count for an ecosystem and source.
func SetDatasetTotalVulnerabilities(ecosystem, source string, count float64) {
	if source == "" {
		source = "unknown"
	}
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	DatasetTotalVulnerabilities.WithLabelValues(ecosystem, source).Set(count)
}
