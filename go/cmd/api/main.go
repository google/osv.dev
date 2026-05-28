// Package main implements the entry point for the production OSV API server.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"cloud.google.com/go/datastore"
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
		logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")
		return errors.New("GOOGLE_CLOUD_PROJECT environment variable is not set")
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
	vulnStore := db.NewVulnerabilityStore(db.VulnStoreConfig{
		Client: dbClient,
		GCS:    clients.NewGCSClient(gcsClient, vulnBucket),
	})
	relationsStore := db.NewRelationsStore(dbClient)

	return api.RunServer(ctx, api.ServerOptions{
		Port:           *port,
		VulnStore:      vulnStore,
		RelationsStore: relationsStore,
	})
}
