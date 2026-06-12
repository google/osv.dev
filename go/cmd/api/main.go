// Package main implements the entry point for the production OSV API server.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/api"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	logger.InitGlobalLogger()
	defer logger.Close()

	port := flag.Int("port", 8000, "port for the OSV API")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		// Fallback to metadata server for Cloud Run
		var err error
		project, err = metadata.ProjectIDWithContext(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")
			return errors.New("GOOGLE_CLOUD_PROJECT environment variable is not set")
		}
	}
	datastoreID := os.Getenv("DATASTORE_DATABASE_ID") // empty string is the (default) database
	dbClient, err := datastore.NewClientWithDatabase(ctx, project, datastoreID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create datastore client", slog.Any("error", err))
		return err
	}
	defer dbClient.Close()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client", slog.Any("error", err))
		return err
	}
	defer gcsClient.Close()
	vulnBucket := os.Getenv("OSV_VULNERABILITIES_BUCKET")
	if vulnBucket == "" {
		logger.ErrorContext(ctx, "OSV_VULNERABILITIES_BUCKET environment variable is not set")
		return errors.New("OSV_VULNERABILITIES_BUCKET environment variable is not set")
	}
	var batchTimeout time.Duration
	if t := os.Getenv("OSV_DB_BATCH_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			batchTimeout = d
		} else {
			logger.ErrorContext(ctx, "Invalid OSV_DB_BATCH_TIMEOUT, using default", slog.Any("error", err))
		}
	}
	var batchMaxElements int
	if m := os.Getenv("OSV_DB_BATCH_MAX_SIZE"); m != "" {
		if val, err := strconv.Atoi(m); err == nil {
			batchMaxElements = val
		} else {
			logger.ErrorContext(ctx, "Invalid OSV_DB_BATCH_MAX_SIZE, using default", slog.Any("error", err))
		}
	}

	vulnStore := db.NewVulnerabilityStore(db.VulnStoreConfig{
		Client:           dbClient,
		GCS:              clients.NewGCSClient(gcsClient, vulnBucket),
		BatchTimeout:     batchTimeout,
		BatchMaxElements: batchMaxElements,
	})
	relationsStore := db.NewRelationsStore(dbClient)
	importFindingsStore := db.NewImportFindingsStore(dbClient, nil, "", "") // The API does not need to talk to GCS, so we can ignore those fields.
	repoIndexStore := db.NewRepoIndexStore(dbClient)
	verboseLogs := strings.EqualFold(os.Getenv("OSV_VERBOSE_LOGGING"), "true")

	var recovererPublisher clients.Publisher
	recovererTopic := os.Getenv("FAILED_TASKS_TOPIC")
	if recovererTopic != "" {
		pubsubClient, err := pubsub.NewClient(ctx, project)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create pubsub client", slog.Any("error", err))
			return err
		}
		defer pubsubClient.Close()
		recovererPublisher = &clients.GCPPublisher{Publisher: pubsubClient.Publisher(recovererTopic)}
	}

	return api.RunServer(ctx, api.ServerOptions{
		Port:                *port,
		VerboseLogs:         verboseLogs,
		VulnStore:           vulnStore,
		RelationsStore:      relationsStore,
		ImportFindingsStore: importFindingsStore,
		RepoIndexStore:      repoIndexStore,
		RecovererPublisher:  recovererPublisher,
	})
}
