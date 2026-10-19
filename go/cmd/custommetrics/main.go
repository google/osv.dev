// Package main for custommetrics calculates and exposes state metrics for Prometheus/GMP and Google Cloud Monitoring.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"cloud.google.com/go/storage"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/metrics"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"google.golang.org/api/iterator"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	kubeStateMetricLastRun    = "prometheus.googleapis.com/kube_cronjob_status_last_successful_time/gauge"
	customMetricCronFreshness = "custom.googleapis.com/cronjob/seconds_since_last_success"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT must be set")
		return errors.New("GOOGLE_CLOUD_PROJECT must be set")
	}

	datastoreID := envOrDefault("DATASTORE_DATABASE_ID", "")
	vulnBucket := envOrDefault("OSV_VULNERABILITIES_BUCKET", "osv-test-vulnerabilities")
	metricsPort := envOrDefault("METRICS_PORT", "9090")

	if metricsPort != "" {
		metrics.StartMetricsServer(ctx, metricsPort)
	}

	dsClient, err := datastore.NewClientWithDatabase(ctx, project, datastoreID)
	if err != nil {
		logger.ErrorContext(ctx, "failed to create datastore client", slog.Any("err", err))
		return err
	}
	defer dsClient.Close()

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "failed to create storage client", slog.Any("err", err))
		return err
	}
	defer gcsClient.Close()

	monitoringClient, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		logger.WarnContext(ctx, "failed to create monitoring client; legacy cron freshness metric disabled", slog.Any("err", err))
	} else {
		defer monitoringClient.Close()
	}

	collector := NewCollector(Stores{
		SourceRepo:     osvdatastore.NewSourceRepositoryStore(dsClient),
		JobData:        osvdatastore.NewJobDataStore(dsClient),
		ImportFindings: osvdatastore.NewImportFindingsStore(dsClient, gcsClient, "", ""),
		GCS:            clients.NewGCSClient(gcsClient, vulnBucket),
	})

	logger.InfoContext(ctx, "custommetrics collector starting")
	collectAll(ctx, collector, monitoringClient, project)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.InfoContext(ctx, "custommetrics collector shutting down")
			return nil
		case <-ticker.C:
			collectAll(ctx, collector, monitoringClient, project)
		}
	}
}

func collectAll(ctx context.Context, collector *Collector, cl *monitoring.MetricClient, project string) {
	collector.CollectMetrics(ctx)

	if cl == nil {
		return
	}
	crons := []string{"exporter"}
	for _, cron := range crons {
		timeSince, err := getCronFreshness(ctx, cl, project, cron)
		if err != nil {
			logger.WarnContext(ctx, "error getting freshness", slog.String("cronjob", cron), slog.Any("err", err))
			continue
		}
		if err := writeCronFreshness(ctx, cl, project, cron, timeSince); err != nil {
			logger.WarnContext(ctx, "error writing freshness", slog.String("cronjob", cron), slog.Any("err", err))
		}
	}
}

func envOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}

func getCronFreshness(ctx context.Context, cl *monitoring.MetricClient, project string, cronjob string) (int64, error) {
	const lookbackDuration = 24 * time.Hour
	now := time.Now()
	req := &monitoringpb.ListTimeSeriesRequest{
		Name:     "projects/" + project,
		Filter:   fmt.Sprintf("metric.type = %q AND metric.labels.cronjob = %q", kubeStateMetricLastRun, cronjob),
		Interval: &monitoringpb.TimeInterval{EndTime: timestamppb.New(now), StartTime: timestamppb.New(now.Add(-lookbackDuration))},
	}
	it := cl.ListTimeSeries(ctx, req)
	ts, err := it.Next()
	if errors.Is(err, iterator.Done) {
		logger.WarnContext(ctx, "last_successful_time was not found for past day", slog.String("cronjob", cronjob))
		return int64(lookbackDuration / time.Second), nil
	} else if err != nil {
		return 0, err
	}
	points := ts.GetPoints()
	if len(points) == 0 {
		logger.WarnContext(ctx, "time series has no points", slog.String("cronjob", cronjob))
		return int64(lookbackDuration / time.Second), nil
	}
	val := points[0].GetValue().GetDoubleValue()

	return time.Now().Unix() - int64(val), nil
}

func writeCronFreshness(ctx context.Context, cl *monitoring.MetricClient, project string, cronjob string, value int64) error {
	now := timestamppb.Now()
	req := &monitoringpb.CreateTimeSeriesRequest{
		Name: "projects/" + project,
		TimeSeries: []*monitoringpb.TimeSeries{{
			Metric: &metric.Metric{
				Type: customMetricCronFreshness,
				Labels: map[string]string{
					"cronjob": cronjob,
				},
			},
			Resource: &monitoredres.MonitoredResource{
				Type: "k8s_cluster",
				Labels: map[string]string{
					"project_id":   project,
					"location":     "us-central1-f",
					"cluster_name": "workers",
				},
			},
			Points: []*monitoringpb.Point{{
				Interval: &monitoringpb.TimeInterval{
					StartTime: now,
					EndTime:   now,
				},
				Value: &monitoringpb.TypedValue{
					Value: &monitoringpb.TypedValue_Int64Value{
						Int64Value: value,
					},
				},
			}},
		}},
	}

	return cl.CreateTimeSeries(ctx, req)
}
