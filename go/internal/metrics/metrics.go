// Package metrics defines shared Prometheus metrics for OSV.dev services and components.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Worker Metrics

	// WorkerTasksProcessed tracks total tasks processed by the worker daemon.
	WorkerTasksProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "worker",
			Name:      "tasks_processed_total",
			Help:      "Total Pub/Sub tasks processed by the worker daemon.",
		},
		[]string{"action", "status", "ecosystem", "source"},
	)

	// WorkerRecordLatency tracks latency from task receive time to completion.
	WorkerRecordLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "worker",
			Name:      "record_latency_seconds",
			Help:      "Latency of processing vulnerability record from receive time.",
			Buckets:   []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"source"},
	)

	// WorkerPublishedToAvailable tracks end-to-end latency between upstream publish time and database availability.
	WorkerPublishedToAvailable = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "worker",
			Name:      "published_to_available_seconds",
			Help:      "End-to-end latency between upstream publish time and OSV database availability.",
			Buckets:   []float64{60, 300, 600, 1800, 3600, 7200, 14400, 28800, 86400},
		},
		[]string{"source"},
	)

	// WorkerFailedTasks tracks total failed tasks in the worker.
	WorkerFailedTasks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "worker",
			Name:      "failed_tasks_total",
			Help:      "Total failed tasks in the worker daemon.",
		},
		[]string{"source", "error_type", "recoverable"},
	)

	// Gitter Metrics

	// GitterRepos tracks total repositories cached by Gitter.
	GitterRepos = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "repos",
			Help:      "Total git repositories cached by Gitter.",
		},
	)

	// GitterCommitsScanned tracks total git commits scanned.
	GitterCommitsScanned = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "commits_scanned_total",
			Help:      "Total git commits scanned by Gitter.",
		},
		[]string{"repo"},
	)

	// GitterOperationDuration tracks duration of git operations.
	GitterOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "operation_duration_seconds",
			Help:      "Duration of git operations in seconds.",
			Buckets:   []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800},
		},
		[]string{"operation"},
	)

	// GitterDataErrors tracks data and repository corruption errors encountered.
	GitterDataErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "data_errors_total",
			Help:      "Data and corruption errors encountered in git repositories.",
		},
		[]string{"error_type"},
	)

	// GitterDiskUsedBytes tracks disk bytes used on the Gitter cache volume.
	GitterDiskUsedBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "disk_used_bytes",
			Help:      "Used bytes on the Gitter cache disk.",
		},
	)

	// GitterDiskCapacityBytes tracks total capacity in bytes of the Gitter cache volume.
	GitterDiskCapacityBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "disk_capacity_bytes",
			Help:      "Total capacity in bytes of the Gitter cache disk.",
		},
	)

	// GitterCommitRangeSize tracks the number of commits in evaluated commit ranges.
	GitterCommitRangeSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "gitter",
			Name:      "commit_range_size_commits",
			Help:      "Number of commits in evaluated affected commit ranges.",
			Buckets:   []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000},
		},
	)

	// Importer & Reconciler & Deleter Metrics

	// ImporterPublishedTasks tracks tasks published to Pub/Sub.
	ImporterPublishedTasks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "importer",
			Name:      "published_tasks_total",
			Help:      "Total tasks published to Pub/Sub by importer.",
		},
		[]string{"source", "topic"},
	)

	// ImporterDiscoveredRecords tracks records discovered during importer runs.
	ImporterDiscoveredRecords = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "importer",
			Name:      "records_discovered_total",
			Help:      "Total vulnerability records discovered by importer.",
		},
		[]string{"source", "status"},
	)

	// ImporterRunDuration tracks duration of importer runs.
	ImporterRunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "osv",
			Subsystem: "importer",
			Name:      "run_duration_seconds",
			Help:      "Duration of importer execution in seconds.",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		},
		[]string{"source"},
	)

	// ImporterUpstreamErrors tracks errors querying upstream sources.
	ImporterUpstreamErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "importer",
			Name:      "upstream_errors_total",
			Help:      "Errors encountered querying upstream vulnerability sources.",
		},
		[]string{"source", "fatal"},
	)

	// ImporterLastNewRecordTimestamp tracks the timestamp of the last new record found for a source.
	ImporterLastNewRecordTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "importer",
			Name:      "last_new_record_timestamp_seconds",
			Help:      "Unix timestamp in seconds of the last new record discovered from source.",
		},
		[]string{"source"},
	)

	// ReconcilerRecordsReconciled tracks records processed by the reconciler.
	ReconcilerRecordsReconciled = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "reconciler",
			Name:      "records_reconciled_total",
			Help:      "Total records processed by the importer reconciler.",
		},
		[]string{"status"},
	)

	// DeleterRefusedDeletions tracks safety threshold coward refusals.
	DeleterRefusedDeletions = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "deleter",
			Name:      "refused_deletions_total",
			Help:      "Count of safety refusals to delete records exceeding deletion percentage threshold.",
		},
	)

	// DeleterUpstreamWithdrawals tracks record withdrawals detected.
	DeleterUpstreamWithdrawals = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "deleter",
			Name:      "upstream_withdrawals_total",
			Help:      "Count of upstream record withdrawals processed.",
		},
		[]string{"source"},
	)

	// Data Quality & RecordChecker Metrics

	// DataQualityFindings tracks linter findings per rule and source.
	DataQualityFindings = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "data_quality",
			Name:      "findings_total",
			Help:      "Total data quality linter findings recorded.",
		},
		[]string{"source", "rule_code", "severity"},
	)

	// RecordCheckerDrift tracks Datastore vs GCS drift.
	RecordCheckerDrift = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "recordchecker",
			Name:      "drift",
			Help:      "Total synchronization drift count between Datastore and GCS.",
		},
		[]string{"type"},
	)

	// RecordCheckerInvalidRecords tracks total invalid records detected.
	RecordCheckerInvalidRecords = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "recordchecker",
			Name:      "invalid_records",
			Help:      "Total invalid records detected by record checker per source.",
		},
		[]string{"source"},
	)

	// Recoverer Metrics

	// RecovererProcessedRecords tracks records processed by recoverer.
	RecovererProcessedRecords = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "osv",
			Subsystem: "recoverer",
			Name:      "processed_records_total",
			Help:      "Total recovery operations processed by recoverer.",
		},
		[]string{"reason"},
	)

	// RecovererActiveQueueLength tracks active recoverer queue length.
	RecovererActiveQueueLength = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "osv",
			Subsystem: "recoverer",
			Name:      "active_queue_length",
			Help:      "Active length of the recovery task queue.",
		},
	)
)
