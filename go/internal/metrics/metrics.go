// Package metrics provides Prometheus metric definitions and exposition for OSV services.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// WorkerTasksProcessedTotal tracks the total number of tasks processed by the worker.
	WorkerTasksProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_worker_tasks_processed_total",
			Help: "Total number of tasks processed by the worker.",
		},
		[]string{"status"},
	)

	// WorkerPublishedToAvailableSeconds tracks the lag between publication and availability.
	WorkerPublishedToAvailableSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "osv_worker_published_to_available_seconds",
			Help:    "Lag between publication and availability in seconds.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 15),
		},
		[]string{"source"},
	)
)

// TaskStatus represents the outcome of processing a worker task.
type TaskStatus string

const (
	TaskStatusSuccess TaskStatus = "success"
	TaskStatusError   TaskStatus = "error"
	TaskStatusSkipped TaskStatus = "skipped"
	TaskStatusUnknown TaskStatus = "unknown"
)

// RecordTaskProcessed increments the task processed counter for a given status.
func RecordTaskProcessed(status TaskStatus) {
	if status == "" {
		status = TaskStatusUnknown
	}
	WorkerTasksProcessedTotal.WithLabelValues(string(status)).Inc()
}

// RecordPublishedToAvailableLag records the lag between publication and availability.
func RecordPublishedToAvailableLag(source string, lag time.Duration) {
	WorkerPublishedToAvailableSeconds.WithLabelValues(source).Observe(lag.Seconds())
}
