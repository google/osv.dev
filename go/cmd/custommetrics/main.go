// Package main for custommetrics calculates and exports custom metrics to Google Cloud Monitoring.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"github.com/google/osv.dev/go/logger"
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
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.Fatal("GOOGLE_CLOUD_PROJECT must be set")
	}
	ctx := context.Background()
	cl, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		logger.Fatal("failed to create monitoring client", slog.Any("err", err))
	}
	defer cl.Close()

	// exporter seconds since last success
	timeSince, err := getCronFreshness(ctx, cl, project, "exporter")
	if err != nil {
		logger.Fatal("error getting freshness", slog.String("cronjob", "exporter"), slog.Any("err", err))
	}
	if err := writeCronFreshness(ctx, cl, project, "exporter", timeSince); err != nil {
		logger.Fatal("error writing freshness", slog.String("cronjob", "exporter"), slog.Any("err", err))
	}
}

func getCronFreshness(ctx context.Context, cl *monitoring.MetricClient, project string, cronjob string) (int64, error) {
	const lookbackDuration = 24 * time.Hour
	req := &monitoringpb.ListTimeSeriesRequest{
		Name:     "projects/" + project,
		Filter:   fmt.Sprintf("metric.type = %q AND metric.labels.cronjob = %q", kubeStateMetricLastRun, cronjob),
		Interval: &monitoringpb.TimeInterval{EndTime: timestamppb.Now(), StartTime: timestamppb.New(time.Now().Add(-lookbackDuration))},
	}
	it := cl.ListTimeSeries(ctx, req)
	ts, err := it.Next()
	if errors.Is(err, iterator.Done) {
		logger.Warn("last_successful_time was not found for past day", slog.String("cronjob", cronjob))
		return int64(lookbackDuration / time.Second), nil
	} else if err != nil {
		return 0, err
	}
	points := ts.GetPoints()
	if len(points) == 0 { // I'm pretty sure iterator.Done would be returned instead.
		logger.Warn("time series has no points", slog.String("cronjob", cronjob))
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
