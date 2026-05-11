// Package main implements the OSV worker for ingesting and enriching upstream vulns sent from the importer
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/worker"
	"github.com/google/osv.dev/go/internal/worker/pipeline/registry"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/osv/ecosystem"
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

	logger.DebugContext(ctx, "worker starting")

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")
		return errors.New("GOOGLE_CLOUD_PROJECT environment variable is not set")
	}
	gitterHost := os.Getenv("GITTER_HOST")
	if gitterHost == "" {
		logger.ErrorContext(ctx, "GITTER_HOST environment variable is not set")
		return errors.New("GITTER_HOST environment variable is not set")
	}

	numWorkers := flag.Int("num-workers", 10, "Number of workers used to process tasks")

	flag.Parse()

	pubsubSubscription := envOrDefault("PUBSUB_SUBSCRIPTION", "tasks")
	datastoreID := envOrDefault("DATASTORE_DATABASE_ID", "") // empty string is the (default) database
	vulnBucket := envOrDefault("OSV_VULNERABILITIES_BUCKET", "osv-test-vulnerabilities")
	failTasksTopic := envOrDefault("FAILED_TASKS_TOPIC", "failed-tasks")
	notifyPyPI, _ := strconv.ParseBool(envOrDefault("NOTIFY_PYPI", "false")) // returns false on error

	// Plug in all the connections to the engine
	dsClient, err := datastore.NewClientWithDatabase(ctx, project, datastoreID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create datastore client", slog.Any("error", err))
		return err
	}
	defer dsClient.Close()

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client", slog.Any("error", err))
		return err
	}
	defer gcsClient.Close()

	psClient, err := pubsub.NewClient(ctx, project)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create pubsub client", slog.Any("error", err))
		return err
	}
	defer psClient.Close()

	stores := worker.Stores{
		SourceRepo: db.NewSourceRepositoryStore(dsClient),
		Vulnerability: db.NewVulnerabilityStore(db.VulnStoreConfig{
			Client:               dsClient,
			GCS:                  clients.NewGCSClient(gcsClient, vulnBucket),
			FailedWritePublisher: &clients.GCPPublisher{Publisher: psClient.Publisher(failTasksTopic)},
		}),
		Relations:      db.NewRelationsStore(dsClient),
		ImportFindings: db.NewImportFindingsStore(dsClient),
	}

	engine := worker.Engine{
		Stores:   stores,
		Pipeline: registry.List,

		GitterHost:        gitterHost,
		GitterClient:      &http.Client{Timeout: 1 * time.Hour},
		EcosystemProvider: ecosystem.DefaultProvider,
	}

	if notifyPyPI {
		engine.NotifyPyPI = true
		engine.Stores.PyPIPublisher = &clients.GCPPublisher{Publisher: psClient.Publisher("pypi-bridge")}
	}

	// Set up and run the subscriber
	sub := psClient.Subscriber(pubsubSubscription)
	sub.ReceiveSettings.MaxOutstandingMessages = *numWorkers
	sub.ReceiveSettings.MaxOutstandingBytes = -1 // no limit - we can give lots of memory to these machines
	sub.ReceiveSettings.MaxExtension = 6 * time.Hour
	sub.ReceiveSettings.MaxDurationPerAckExtension = 10 * time.Minute
	subscriber := worker.Subscriber{
		Engine:    engine,
		PubSubSub: sub,
	}

	return subscriber.Run(ctx)
}

// envOrDefault retrieves the value of the environment variable named by the key.
// If the variable is not present in the environment, it returns the defaultValue.
func envOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}
