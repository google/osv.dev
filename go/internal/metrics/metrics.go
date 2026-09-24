// Package metrics provides Prometheus metric definitions and exposition for OSV services.
package metrics

import (
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
