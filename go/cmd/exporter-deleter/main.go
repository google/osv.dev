// Package main runs the exporter-deleter, which removes objects from the
// exporter's GCS bucket that are no longer part of the latest export.
// See the README.md for more details.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"go.opentelemetry.io/otel"
	"google.golang.org/api/option"
)

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()

	ctx, span := otel.Tracer("exporter-deleter").Start(ctx, "exporter-deleter")
	defer span.End()

	bucketName := flag.String("bucket", "", "GCS bucket the exporter writes to, to delete stale objects from.")
	minAge := flag.Duration("min-age", time.Hour, "Only delete objects last updated at least this long ago, to avoid racing an in-progress export.")
	thresholdPct := flag.Float64("threshold-pct", 2.0, "Refuse to delete anything if more than this percent of vulnerability files would be deleted.")
	dryRun := flag.Bool("dry-run", false, "Log what would be deleted without deleting anything.")
	numWorkers := flag.Int("workers", 100, "Number of concurrent list/delete operations.")

	flag.Parse()

	logger.InfoContext(ctx, "exporter-deleter starting",
		slog.String("bucket", *bucketName),
		slog.Duration("min-age", *minAge),
		slog.Float64("threshold-pct", *thresholdPct),
		slog.Bool("dry-run", *dryRun),
		slog.Int("workers", *numWorkers))

	if *bucketName == "" {
		logger.FatalContext(ctx, "-bucket must be set")
	}

	storageClient, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "failed to create storage client", slog.Any("err", err))
	}
	defer storageClient.Close()

	cfg := deleterConfig{
		MinAge:       *minAge,
		ThresholdPct: *thresholdPct,
		DryRun:       *dryRun,
		NumWorkers:   *numWorkers,
		Now:          time.Now,
	}
	if err := runDeleter(ctx, clients.NewGCSClient(storageClient, *bucketName), cfg); err != nil {
		logger.FatalContext(ctx, "exporter-deleter failed", slog.Any("err", err))
	}
	logger.InfoContext(ctx, "exporter-deleter completed successfully")
}
