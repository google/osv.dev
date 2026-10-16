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
		[]string{"status", "action", "work_pool"},
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

	// WorkerRecordLatencySeconds tracks the duration of processing a single task in the worker.
	WorkerRecordLatencySeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "osv_worker_record_latency_seconds",
			Help:    "Latency in seconds to process a vulnerability record in the worker from task receive to finish.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 14),
		},
	)

	// WorkerFailedTasksTotal tracks worker task failures by error type and recoverability.
	WorkerFailedTasksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_worker_failed_tasks_total",
			Help: "Total number of failed worker tasks by error type and recoverability.",
		},
		[]string{"error_type", "recoverable"},
	)

	// DeleterUpstreamWithdrawalsTotal tracks upstream vulnerability withdrawals processed.
	DeleterUpstreamWithdrawalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_deleter_upstream_withdrawals_total",
			Help: "Total number of upstream vulnerability withdrawals processed by source.",
		},
		[]string{"source"},
	)

	// DeleterRefusedDeletionsTotal tracks the number of deletions refused due to safety threshold limits.
	DeleterRefusedDeletionsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_deleter_refused_deletions_total",
			Help: "Number of records refused for deletion due to safety threshold limits by source.",
		},
		[]string{"source"},
	)

	// ReconcilerRecordsReconciledTotal tracks the latest importer-reconciler record counts by status.
	ReconcilerRecordsReconciledTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_reconciler_records_reconciled_total",
			Help: "Number of records evaluated by importer-reconciler by status (up_to_date, missing, outdated).",
		},
		[]string{"status"},
	)

	// ImporterLastNewRecordTimestampSeconds tracks the Unix timestamp of the most recent record update per source.
	ImporterLastNewRecordTimestampSeconds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_importer_last_new_record_timestamp_seconds",
			Help: "Unix timestamp in seconds of the last new or updated record per upstream source.",
		},
		[]string{"source"},
	)

	// ImporterRecordsDiscoveredTotal tracks the total number of records discovered/ingested per upstream source.
	ImporterRecordsDiscoveredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_importer_records_discovered_total",
			Help: "Total number of vulnerability records discovered and processed per upstream source.",
		},
		[]string{"source"},
	)

	// DatasetTotalVulnerabilities tracks the total number of exported vulnerabilities per ecosystem.
	DatasetTotalVulnerabilities = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_dataset_total_vulnerabilities",
			Help: "Total number of vulnerabilities in the exported dataset by ecosystem (ecosystem=\"all\" for global unique count).",
		},
		[]string{"ecosystem"},
	)

	// ExportZipSizeBytes tracks the size in bytes of exported all.zip archives in GCS.
	ExportZipSizeBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_export_zip_size_bytes",
			Help: "Size in bytes of exported all.zip archives by ecosystem.",
		},
		[]string{"ecosystem"},
	)

	// RecordCheckerDrift tracks Datastore vs. GCS synchronization drift discrepancies by drift type.
	RecordCheckerDrift = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_recordchecker_drift",
			Help: "Current number of Datastore vs. GCS drift discrepancies by type.",
		},
		[]string{"type"},
	)

	// RecordCheckerInvalidRecords tracks invalid/drifted records detected by recordchecker per source.
	RecordCheckerInvalidRecords = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_recordchecker_invalid_records",
			Help: "Current number of invalid or missing GCS records detected by recordchecker by source.",
		},
		[]string{"source"},
	)

	// RecovererProcessedRecordsTotal tracks recovery tasks processed by the recoverer daemon.
	RecovererProcessedRecordsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_recoverer_processed_records_total",
			Help: "Total number of recovery tasks processed by recoverer by reason and status.",
		},
		[]string{"reason", "status"},
	)

	// DataQualityFindingsTotal tracks active osv-linter findings (ImportFinding entities) by source, rule code, and severity.
	DataQualityFindingsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osv_data_quality_findings_total",
			Help: "Active vulnerability data quality linter findings by upstream source, rule code, and severity.",
		},
		[]string{"source", "rule_code", "severity"},
	)

	// GitterCommitsScannedTotal tracks the total number of Git commits scanned/evaluated by Gitter.
	GitterCommitsScannedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "osv_gitter_commits_scanned_total",
			Help: "Total number of Git commits scanned and evaluated by Gitter.",
		},
	)

	// GitterDataErrorsTotal tracks Git data errors encountered by Gitter (e.g. bad_hash, bad_repo_url).
	GitterDataErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "osv_gitter_data_errors_total",
			Help: "Total number of Git data errors encountered by Gitter by error type.",
		},
		[]string{"error_type"},
	)

	// GitterOperationDurationSeconds tracks latency distributions for Gitter operations.
	GitterOperationDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "osv_gitter_operation_duration_seconds",
			Help:    "Duration in seconds of Gitter HTTP endpoints and Git operations.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 15),
		},
		[]string{"operation", "status"},
	)

	// GitterDiskUsedBytes tracks used bytes on Gitter's persistent disk cache.
	GitterDiskUsedBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "osv_gitter_disk_used_bytes",
			Help: "Bytes used on Gitter's persistent SSD cache disk.",
		},
	)

	// GitterDiskTotalBytes tracks total capacity in bytes on Gitter's persistent disk cache.
	GitterDiskTotalBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "osv_gitter_disk_total_bytes",
			Help: "Total capacity in bytes of Gitter's persistent SSD cache disk.",
		},
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

// TaskAction represents the type of worker task action.
type TaskAction string

const (
	TaskActionUpdate  TaskAction = "update"
	TaskActionDelete  TaskAction = "delete"
	TaskActionUnknown TaskAction = "unknown"
)

// WorkerErrorType classifies the stage where a worker task failed.
type WorkerErrorType string

const (
	WorkerErrorParse        WorkerErrorType = "parse_error"
	WorkerErrorSourceRepo   WorkerErrorType = "source_repo_error"
	WorkerErrorDatastoreGet WorkerErrorType = "datastore_read_error"
	WorkerErrorEnrich       WorkerErrorType = "enrich_error"
	WorkerErrorCommitEnum   WorkerErrorType = "commit_enumeration_error"
	WorkerErrorWrite        WorkerErrorType = "write_error"
	WorkerErrorDelete       WorkerErrorType = "delete_error"
)

// GitterErrorType classifies Git data errors in Gitter.
type GitterErrorType string

const (
	GitterErrorBadHash    GitterErrorType = "bad_hash"
	GitterErrorBadRepoURL GitterErrorType = "bad_repo_url"
	GitterErrorFetch      GitterErrorType = "fetch_error"
)

func init() {
	// Pre-initialize known counter label combinations to 0 so panels render 0 instead of "No data" when healthy.
	for _, errType := range []WorkerErrorType{
		WorkerErrorParse,
		WorkerErrorSourceRepo,
		WorkerErrorDatastoreGet,
		WorkerErrorEnrich,
		WorkerErrorCommitEnum,
		WorkerErrorWrite,
		WorkerErrorDelete,
	} {
		WorkerFailedTasksTotal.WithLabelValues(string(errType), "true")
		WorkerFailedTasksTotal.WithLabelValues(string(errType), "false")
	}

	for _, reason := range []string{"gcs_retry", "gcs_missing", "gcs_gen_mismatch", "generic"} {
		RecovererProcessedRecordsTotal.WithLabelValues(reason, string(TaskStatusSuccess))
		RecovererProcessedRecordsTotal.WithLabelValues(reason, string(TaskStatusError))
	}

	for _, gitterErr := range []GitterErrorType{GitterErrorBadHash, GitterErrorBadRepoURL, GitterErrorFetch} {
		GitterDataErrorsTotal.WithLabelValues(string(gitterErr))
	}
}

// RecordTaskProcessed increments the task processed counter with default action and work_pool labels.
func RecordTaskProcessed(status TaskStatus) {
	RecordWorkerTask(status, TaskActionUnknown, "unknown")
}

// RecordWorkerTask increments the task processed counter for a given status, action, and work pool.
func RecordWorkerTask(status TaskStatus, action TaskAction, workPool string) {
	if status == "" {
		status = TaskStatusUnknown
	}
	if action == "" {
		action = TaskActionUnknown
	}
	if workPool == "" {
		workPool = "default"
	}
	WorkerTasksProcessedTotal.WithLabelValues(string(status), string(action), workPool).Inc()
}

// RecordWorkerLatency records the duration of processing a worker task.
func RecordWorkerLatency(duration time.Duration) {
	WorkerRecordLatencySeconds.Observe(duration.Seconds())
}

// RecordWorkerFailedTask increments the failed worker task counter.
func RecordWorkerFailedTask(errType WorkerErrorType, recoverable bool) {
	recStr := "false"
	if recoverable {
		recStr = "true"
	}
	WorkerFailedTasksTotal.WithLabelValues(string(errType), recStr).Inc()
}

// RecordPublishedToAvailableLag records the lag between publication and availability.
func RecordPublishedToAvailableLag(source string, lag time.Duration) {
	if source == "" {
		source = "unknown"
	}
	WorkerPublishedToAvailableSeconds.WithLabelValues(source).Observe(lag.Seconds())
}

// RecordSourceRecordDiscovered updates the freshness timestamp and discovered counter for an upstream source.
func RecordSourceRecordDiscovered(source string, ts time.Time) {
	if source == "" {
		return
	}
	ImporterRecordsDiscoveredTotal.WithLabelValues(source).Inc()
	if !ts.IsZero() {
		ImporterLastNewRecordTimestampSeconds.WithLabelValues(source).Set(float64(ts.Unix()))
	}
}

// RecordUpstreamWithdrawal increments the withdrawal counter for an upstream source.
func RecordUpstreamWithdrawal(source string) {
	if source == "" {
		source = "unknown"
	}
	DeleterUpstreamWithdrawalsTotal.WithLabelValues(source).Inc()
}

// RecordRecovererTask increments the recoverer processed counter.
func RecordRecovererTask(reason string, status TaskStatus) {
	if reason == "" {
		reason = "generic"
	}
	if status == "" {
		status = TaskStatusUnknown
	}
	RecovererProcessedRecordsTotal.WithLabelValues(reason, string(status)).Inc()
}

// RecordGitterCommitsScanned adds n commits to the Gitter commits scanned counter.
func RecordGitterCommitsScanned(n int) {
	if n > 0 {
		GitterCommitsScannedTotal.Add(float64(n))
	}
}

// RecordGitterDataError increments the Gitter data error counter for the given error type.
func RecordGitterDataError(errType GitterErrorType) {
	GitterDataErrorsTotal.WithLabelValues(string(errType)).Inc()
}

// RecordGitterOperation records the duration and HTTP status class of a Gitter endpoint call.
func RecordGitterOperation(operation string, status string, duration time.Duration) {
	GitterOperationDurationSeconds.WithLabelValues(operation, status).Observe(duration.Seconds())
}
