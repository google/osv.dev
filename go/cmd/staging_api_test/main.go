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

// Package main runs staging API performance and load tests by fetching vulnerability
// data from the exported bucket and generating concurrent traffic across OSV endpoints.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
)

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	return fallback
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	defaultBucket := envOrDefault("OSV_VULNERABILITIES_BUCKET", "osv-test-vulnerabilities")
	defaultAPIURL := envOrDefault("API_BASE_URL", "https://api.test.osv.dev/v1")
	defaultZipPath := envOrDefault("ZIP_FILE_PATH", "all.zip")

	bucketFlag := flag.String("bucket", defaultBucket, "GCS bucket to read exported vulnerabilities from")
	zipPathFlag := flag.String("zip-path", defaultZipPath, "Path of all.zip inside the GCS bucket")
	localZipFlag := flag.String("local-zip", os.Getenv("LOCAL_ZIP"), "Optional local path to all.zip (skips GCS download if specified)")
	apiURLFlag := flag.String("api-url", defaultAPIURL, "Base URL for the OSV API under test")
	durationFlag := flag.Duration("duration", 5*time.Hour, "Total run duration of the load test (e.g. 5h, 30m)")
	seedFlag := flag.Uint64("seed", 0, "Random seed (0 to generate a random seed)")

	vulnRateFlag := flag.Int("vuln-rate", 50, "Number of GET /v1/vulns/{id} requests per second")
	versionRateFlag := flag.Int("version-rate", 80, "Number of POST /v1/query (version) requests per second")
	packageRateFlag := flag.Int("package-rate", 20, "Number of POST /v1/query (package) requests per second")
	purlRateFlag := flag.Int("purl-rate", 30, "Number of POST /v1/query (purl) requests per second")
	batchRateFlag := flag.Int("batch-rate", 3, "Number of POST /v1/querybatch (normal) requests per second")
	largeBatchRateFlag := flag.Int("large-batch-rate", 2, "Number of POST /v1/querybatch (large) requests per second")
	maxBatchSizeFlag := flag.Int("max-batch-size", 100, "Maximum number of queries per standard /v1/querybatch request (1-1000)")
	maxLargeBatchSizeFlag := flag.Int("max-large-batch-size", 100, "Maximum number of queries per heavy /v1/querybatch request (1-1000)")
	statsIntervalFlag := flag.Duration("stats-interval", 30*time.Second, "Interval between logging summary statistics")

	flag.Parse()

	seed := *seedFlag
	if seed == 0 {
		seed = rand.Uint64() //nolint:gosec // math/rand is sufficient for mock traffic generation
	}
	logger.Info("Starting staging API test", "seed", seed)
	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(seed, seed^0x5DEECE66D))

	var gcsClient *storage.Client
	if *localZipFlag == "" {
		var err error
		gcsClient, err = storage.NewClient(ctx)
		if err != nil {
			logger.Error("Failed to create GCS client", "error", err)

			return fmt.Errorf("failed to create GCS client: %w", err)
		}
		defer gcsClient.Close()
	}

	pools, err := LoadQueryPools(ctx, gcsClient, *bucketFlag, *zipPathFlag, *localZipFlag, rng)
	if err != nil {
		logger.Error("Failed to load query pools from vulnerability records", "error", err)

		return fmt.Errorf("failed to load query pools: %w", err)
	}

	logger.Info("Loaded vulnerability query pools successfully",
		"totalVulns", len(pools.VulnQueryIDs),
		"totalPackages", len(pools.PackageQueryIDs),
		"totalEcosystems", len(pools.EcosystemMap),
		"largeBatchPoolSize", len(pools.LargeBatchQueryIDs),
	)

	cfg := GeneratorConfig{
		BaseURL:                *apiURLFlag,
		Duration:               *durationFlag,
		VulnRate:               *vulnRateFlag,
		VersionRate:            *versionRateFlag,
		PackageRate:            *packageRateFlag,
		PURLRate:               *purlRateFlag,
		BatchRate:              *batchRateFlag,
		LargeBatchRate:         *largeBatchRateFlag,
		MaxBatchQuerySize:      *maxBatchSizeFlag,
		MaxLargeBatchQuerySize: *maxLargeBatchSizeFlag,
		StatsInterval:          *statsIntervalFlag,
	}

	_, err = RunTrafficGenerator(ctx, nil, pools, cfg, seed)
	if err != nil {
		logger.Error("Traffic generator encountered an error", "error", err)

		return err
	}

	logger.Info("Staging API test completed successfully")

	return nil
}
