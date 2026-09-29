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

// Package main runs the cron job to generate Vanir signatures for modified vulnerabilities.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strings"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/vanir"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"google.golang.org/api/option"
)

func main() {
	var (
		batchSize  int
		maxWorkers int
		dryRun     bool
		hours      int
		pythonBin  string
		scriptPath string
	)

	flag.IntVar(&batchSize, "batch-size", 100, "Number of vulnerabilities to process in each batch.")
	flag.IntVar(&maxWorkers, "max-workers", 10, "Maximum number of parallel batch workers.")
	flag.BoolVar(&dryRun, "dry-run", false, "Perform a dry run without modifying GCS or Datastore.")
	flag.IntVar(&hours, "hours", 0, "Number of hours back to process modified records.")
	flag.StringVar(&pythonBin, "python-bin", "python3", "Python interpreter binary to use.")
	flag.StringVar(&scriptPath, "script-path", "/usr/local/bin/generate_signatures.py", "Path to the Python Vanir signature generation script.")
	flag.Parse()

	logger.InitGlobalLogger()
	defer logger.Close()

	ctx := context.Background()

	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		logger.FatalContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable not set")
	}

	bucketName := strings.TrimPrefix(os.Getenv("OSV_VULNERABILITIES_BUCKET"), "gs://")
	if bucketName == "" {
		logger.FatalContext(ctx, "OSV_VULNERABILITIES_BUCKET environment variable not set")
	}

	datastoreID := os.Getenv("DATASTORE_DATABASE_ID")
	dsClient, err := datastore.NewClientWithDatabase(ctx, projectID, datastoreID, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "Failed to create Datastore client", slog.Any("error", err))
	}
	defer dsClient.Close()

	storageClient, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "Failed to create GCS client", slog.Any("error", err))
	}
	defer storageClient.Close()

	gcsClient := clients.NewGCSClient(storageClient, bucketName)
	vulnStore := osvdatastore.NewVulnerabilityStore(osvdatastore.VulnStoreConfig{
		Client: dsClient,
		GCS:    gcsClient,
	})
	jobStore := osvdatastore.NewJobDataStore(dsClient)
	generator := vanir.NewPythonGenerator(pythonBin, scriptPath)

	runner := &vanir.Runner{
		VulnStore: vulnStore,
		JobStore:  jobStore,
		Generator: generator,
		Config: vanir.Config{
			BatchSize:  batchSize,
			MaxWorkers: maxWorkers,
			DryRun:     dryRun,
			Hours:      hours,
		},
	}

	if err := runner.Run(ctx); err != nil {
		logger.FatalContext(ctx, "Vanir signature generation job failed", slog.Any("error", err))
	}
}
