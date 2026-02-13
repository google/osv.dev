package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/importer"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/hashicorp/go-retryablehttp"
)

func main() {
	logger.InitGlobalLogger()

	strictValidation := flag.Bool("strict-validation", false, "Fail to import entries that do not pass validation.")
	delete := flag.Bool("delete", false, "Bypass importing and propagate record deletions from source to Datastore")
	deleteThresholdPct := flag.Float64("delete-threshold-pct", 10.0, "More than this percent of records for a given source being deleted triggers an error")
	workDir := flag.String("work-dir", "/work", "Work directory for git repos")
	numWorkers := flag.Int("num-workers", 50, "Number of workers to use for importing")

	flag.Parse()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.Fatal("GOOGLE_CLOUD_PROJECT environment variable is not set")
	}

	config := importer.Config{
		StrictValidation: *strictValidation,
		NumWorkers:       *numWorkers,
		GitWorkDir:       filepath.Join(*workDir, "sources"),
	}

	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = 3
	httpClient.RetryWaitMin = 1 * time.Second
	httpClient.RetryWaitMax = 4 * time.Second
	httpClient.Logger = importer.RetryableHTTPLeveledLogger{}
	config.HTTPClient = httpClient.StandardClient()

	datastoreClient, err := datastore.NewClient(context.Background(), project)
	if err != nil {
		logger.Fatal("Failed to create datastore client", slog.Any("error", err))
	}
	config.SourceRepoStore = db.NewSourceRepositoryStore(datastoreClient)

	psClient, err := pubsub.NewClient(context.Background(), project)
	if err != nil {
		logger.Fatal("Failed to create pubsub client", slog.Any("error", err))
	}
	config.Publisher = &clients.GCPPublisher{Publisher: psClient.Publisher(importer.TasksTopic)}

	storageClient, err := storage.NewClient(context.Background())
	if err != nil {
		logger.Fatal("Failed to create GCS client", slog.Any("error", err))
	}
	config.GCSProvider = clients.NewGCSStorageProvider(storageClient)

	if *delete {
		_ = deleteThresholdPct
		logger.Fatal("delete not implemented yet")
	}

	if err := importer.Run(context.Background(), config); err != nil {
		logger.Fatal("Importer failed", slog.Any("error", err))
	}
}
