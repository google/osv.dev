// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main implements the OSV failed task recoverer.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/gitter"
	"github.com/google/osv.dev/go/internal/recoverer"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/hashicorp/go-retryablehttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type retryableHTTPLogger struct{}

func (r retryableHTTPLogger) Error(msg string, keysAndValues ...any) {
	logger.Error(msg, keysAndValues...)
}

func (r retryableHTTPLogger) Info(msg string, keysAndValues ...any) {
	logger.Info(msg, keysAndValues...)
}

func (r retryableHTTPLogger) Debug(msg string, keysAndValues ...any) {
	logger.Debug(msg, keysAndValues...)
}

func (r retryableHTTPLogger) Warn(msg string, keysAndValues ...any) {
	logger.Warn(msg, keysAndValues...)
}

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

	logger.InfoContext(ctx, "recoverer starting")

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")

		return errors.New("GOOGLE_CLOUD_PROJECT environment variable is not set")
	}

	numWorkers := flag.Int("num-workers", 10, "Number of workers used to process recovery tasks")
	flag.Parse()

	pubsubSubscription := envOrDefault("FAILED_TASKS_SUBSCRIPTION", "recovery")
	tasksTopic := envOrDefault("WORKER_TASK_TOPIC", "tasks")
	datastoreID := envOrDefault("DATASTORE_DATABASE_ID", "")
	vulnBucket := envOrDefault("OSV_VULNERABILITIES_BUCKET", "osv-test-vulnerabilities")
	defaultTaskPool := envOrDefault("DEFAULT_TASK_POOL", "default")
	reimportTaskPool := envOrDefault("REIMPORT_TASK_POOL", "reimport")
	gitterHost := os.Getenv("GITTER_HOST")

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

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 4 * time.Second
	retryClient.Logger = retryableHTTPLogger{}
	retryClient.HTTPClient.Transport = otelhttp.NewTransport(http.DefaultTransport)
	httpClient := retryClient.StandardClient()

	var gitterClient gitter.Client
	if gitterHost != "" {
		var err error
		gitterClient, err = gitter.NewClient(gitterHost, httpClient)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create gitter client", slog.Any("error", err))

			return err
		}
	} else {
		logger.WarnContext(ctx, "GITTER_HOST is not set; git source recovery may fail")
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			SourceRepo:      osvdatastore.NewSourceRepositoryStore(dsClient),
			Relations:       osvdatastore.NewRelationsStore(dsClient),
			GCS:             clients.NewGCSClient(gcsClient, vulnBucket),
			GCSProvider:     clients.NewGCSStorageProvider(gcsClient),
			Publisher:       &clients.GCPPublisher{Publisher: psClient.Publisher(tasksTopic)},
		},
		GitterClient:     gitterClient,
		HTTPClient:       httpClient,
		DefaultTaskPool:  defaultTaskPool,
		ReimportTaskPool: reimportTaskPool,
	})

	sub := psClient.Subscriber(pubsubSubscription)
	sub.ReceiveSettings.MaxOutstandingMessages = *numWorkers
	sub.ReceiveSettings.MaxOutstandingBytes = -1
	sub.ReceiveSettings.MaxExtension = 6 * time.Hour
	sub.ReceiveSettings.MaxDurationPerAckExtension = 10 * time.Minute

	logger.InfoContext(ctx, "recoverer listening for messages",
		slog.String("subscription", pubsubSubscription),
		slog.String("topic", tasksTopic))

	return rec.Run(ctx, sub)
}

func envOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}
