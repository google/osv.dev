// Package main implements the entry point for the OSV website server in Go.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/gcs"
	"github.com/google/osv.dev/go/internal/website"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/redis/go-redis/v9"
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

	defaultPort := 8000
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			defaultPort = p
		} else {
			logger.ErrorContext(ctx, "Invalid PORT environment variable, using default", slog.Any("error", err))
		}
	}

	port := flag.Int("port", defaultPort, "port for the website server")
	staticDir := flag.String("static-dir", "dist", "directory containing static assets")
	docsDir := flag.String("docs-dir", "docs", "directory containing API docs")
	flag.Parse()

	staticFiles, err := getStaticFS(*staticDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load static filesystem", slog.String("dir", *staticDir), slog.Any("error", err))

		return fmt.Errorf("failed to load static filesystem %q: %w", *staticDir, err)
	}

	docsFiles, err := getDocsFS(*docsDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load docs filesystem", slog.String("dir", *docsDir), slog.Any("error", err))

		return fmt.Errorf("failed to load docs filesystem %q: %w", *docsDir, err)
	}

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
	dbClient, err := datastore.NewClientWithDatabase(ctx, project, datastoreID, datastore.WithIgnoreFieldMismatch())
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

	linterBucket := os.Getenv("OSV_LINTER_BUCKET")
	if linterBucket == "" {
		linterBucket = "osv-test-public-import-logs"
	}

	var redisClient redis.Cmdable
	if redisHost := os.Getenv("REDISHOST"); redisHost != "" {
		redisPort := os.Getenv("REDISPORT")
		if redisPort == "" {
			redisPort = "6379"
		}
		rdb := redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%s", redisHost, redisPort),
		})
		defer func() {
			if err := rdb.Close(); err != nil {
				logger.ErrorContext(ctx, "Failed to close redis client", slog.Any("error", err))
			}
		}()
		redisClient = rdb
	}

	bypassOAuth := strings.EqualFold(os.Getenv("BYPASS_OAUTH_FOR_LOCAL_DEV"), "true") ||
		os.Getenv("BYPASS_OAUTH_FOR_LOCAL_DEV") == "1" ||
		strings.EqualFold(os.Getenv("BYPASS_OAUTH_FOR_LOCAL_DEV"), "t")

	stores := website.Stores{
		Vuln: db.NewVulnerabilityStore(db.VulnStoreConfig{
			Client: dbClient,
			GCS:    clients.NewGCSClient(gcsClient, vulnBucket),
		}),
		Relations:  db.NewRelationsStore(dbClient),
		SourceRepo: db.NewSourceRepositoryStore(dbClient),
		VulnSearch: db.NewVulnerabilitySearchStore(dbClient, redisClient),
		Linter:     gcs.NewLinterStore(gcsClient.Bucket(linterBucket), "linter-result/"),
		Triage:     gcs.NewTriageStore(gcsClient),
	}

	apiURL := os.Getenv("OSV_API_URL")
	if apiURL == "" {
		apiURL = os.Getenv("API_URL")
	}
	if apiURL == "" {
		apiURL = "api.osv.dev"
	}

	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		secretKey = os.Getenv("FLASK_SECRET_KEY")
	}
	if secretKey == "" {
		secretKey = os.Getenv("SECRET_KEY")
	}
	if secretKey == "" && !bypassOAuth {
		logger.WarnContext(ctx, "SESSION_SECRET_KEY environment variable is not set, authentication will not work")
	}

	srv, err := website.NewServer(website.Config{
		StaticFS: staticFiles,
		DocsFS:   docsFiles,
		Stores:   stores,
		APIURL:   apiURL,
		Auth: website.AuthConfig{
			ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
			SecretKey:    secretKey,
			BypassOAuth:  bypassOAuth,
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create website server", slog.Any("error", err))

		return fmt.Errorf("failed to create website server: %w", err)
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		url := fmt.Sprintf("http://localhost:%d", *port)
		logger.InfoContext(ctx, "Starting OSV website server at "+url, slog.Int("port", *port), slog.String("url", url))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		logger.ErrorContext(ctx, "Server error", slog.Any("error", err))
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		logger.InfoContext(shutdownCtx, "Shutting down website server...")
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(shutdownCtx, "Error during server shutdown", slog.Any("error", err))

			return err
		}
	}

	return nil
}
