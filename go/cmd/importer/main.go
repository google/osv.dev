// Package main for importer synchronizes vulnerability data from various sources into the OSV ecosystem.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/importer"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/hashicorp/go-retryablehttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/api/option"
)

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()
	ctx, span := otel.Tracer("importer").Start(context.Background(), "importer",
		trace.WithAttributes(attribute.Float64("override_sample_rate", importerSampleRate())))
	defer span.End()

	strictValidation := flag.Bool("strict-validation", false, "Do not import entries if they fail validation. "+
		"Note: this only applies to SourceRepositories with strict_validation=true")
	runDelete := flag.Bool("delete", false, "Bypass importing and propagate record deletions from source to Datastore")
	deleteThresholdPct := flag.Float64("delete-threshold-pct", 10.0, "More than this percent of records for a given source being deleted triggers an error")
	workDir := flag.String("work-dir", "/work", "Work directory for git repos")
	numWorkers := flag.Int("num-workers", 50, "Number of workers to use for importing")

	flag.Parse()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.FatalContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")
	}

	config := importer.Config{
		StrictValidation: *strictValidation,
		DeleteThreshold:  *deleteThresholdPct,
		NumWorkers:       *numWorkers,
		GitWorkDir:       filepath.Join(*workDir, "sources"),
		SampleRate:       vulnerabilitySampleRate(),
	}

	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = 3
	httpClient.RetryWaitMin = 1 * time.Second
	httpClient.RetryWaitMax = 4 * time.Second
	httpClient.Logger = importer.RetryableHTTPLeveledLogger{}
	config.HTTPClient = httpClient.StandardClient()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	datastoreClient, err := datastore.NewClient(ctx, project)
	if err != nil {
		logger.FatalContext(ctx, "Failed to create datastore client", slog.Any("error", err))
	}
	config.SourceRepoStore = db.NewSourceRepositoryStore(datastoreClient)
	// Needed for deletions only
	config.VulnerabilityStore = db.NewVulnerabilityStore(datastoreClient)

	psClient, err := pubsub.NewClient(ctx, project)
	if err != nil {
		logger.FatalContext(ctx, "Failed to create pubsub client", slog.Any("error", err))
	}
	config.Publisher = &clients.GCPPublisher{Publisher: psClient.Publisher(importer.TasksTopic)}

	// We are posssibly reading a lot of vulnerabilities from GCS, so disable telemetry (disables trace spans).
	storageClient, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "Failed to create GCS client", slog.Any("error", err))
	}
	config.GCSProvider = clients.NewGCSStorageProvider(storageClient)

	if *runDelete {
		if err := importer.RunDeletions(ctx, config); err != nil {
			logger.FatalContext(ctx, "Importer-deleter failed", slog.Any("error", err))
		}
		logger.InfoContext(ctx, "Importer-deleter completed successfully")
	} else {
		if err := importer.Run(ctx, config); err != nil {
			logger.FatalContext(ctx, "Importer failed", slog.Any("error", err))
		}
		logger.InfoContext(ctx, "Importer completed successfully")
	}
}

// importerSampleRate returns the sample rate for the high-level importer orchestration.
// This covers the discovery process: starting up, listing repositories, and identifying changed files.
// e.g. importer start -> handleImportGit -> identify changed files -> end
// It is set to 0.05 (5%) by default, but can be overridden by the
// IMPORT_TRACE_SAMPLE_RATE environment variable.
func importerSampleRate() float64 {
	rate := 0.05
	if val := os.Getenv("IMPORT_TRACE_SAMPLE_RATE"); val != "" {
		rate, _ = strconv.ParseFloat(val, 64)
	}

	return rate
}

// vulnerabilitySampleRate returns the sample rate for individual vulnerability entries.
// This decision is made in the importer but persists as the record is published to
// Pub/Sub and processed by the downstream worker.
// e.g. read/parse record -> publish to Pub/Sub -> [worker picks up] -> enumerate versions/commits
// It is set to 0.05 (5%) by default, but can be overridden by the
// TRACE_SAMPLE_RATE environment variable.
func vulnerabilitySampleRate() float64 {
	rate := 0.05
	if val := os.Getenv("TRACE_SAMPLE_RATE"); val != "" {
		rate, _ = strconv.ParseFloat(val, 64)
	}

	return rate
}
