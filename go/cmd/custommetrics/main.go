// Package main for custommetrics calculates and exports custom metrics to Google Cloud Monitoring.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"github.com/google/osv.dev/go/logger"
	"go.opentelemetry.io/otel"
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
	ctx := context.Background()
	logger.InitGlobalLogger(ctx)
	defer logger.Close()

	ctx, span := otel.Tracer("custommetrics").Start(ctx, "custommetrics")
	defer span.End()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.FatalContext(ctx, "GOOGLE_CLOUD_PROJECT must be set")
	}
	cl, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		logger.FatalContext(ctx, "failed to create monitoring client", slog.Any("err", err))
	}
	defer cl.Close()

	// cronjob seconds since last success
	crons := []string{"exporter"}
	for _, cron := range crons {
		timeSince, err := getCronFreshness(ctx, cl, project, cron)
		if err != nil {
			logger.FatalContext(ctx, "error getting freshness", slog.String("cronjob", cron), slog.Any("err", err))
		}
		if err := writeCronFreshness(ctx, cl, project, cron, timeSince); err != nil {
			logger.FatalContext(ctx, "error writing freshness", slog.String("cronjob", cron), slog.Any("err", err))
		}
	}
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
	if len(points) == 0 { // I'm pretty sure iterator.Done would be returned instead.
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
					"project_id": project,
					// hard-coded cluster not ideal, but this is the only cluster in the instance.
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
