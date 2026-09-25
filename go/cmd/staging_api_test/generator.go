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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/osv.dev/go/logger"
)

// GeneratorConfig holds configuration for the API load test generator.
type GeneratorConfig struct {
	// BaseURL is the root URL of the OSV API under test (e.g. "https://api.test.osv.dev/v1").
	BaseURL string

	// Duration is the total execution time for the load test.
	Duration time.Duration

	// VulnRate is the sustained rate of GET /v1/vulns/{id} requests per second.
	// It tests the endpoint for fetching full vulnerability details by OSV ID (e.g. GHSA-..., CVE-...).
	VulnRate int

	// VersionRate is the sustained rate of POST /v1/query (package + version) requests per second.
	// It simulates standard scanner checks (e.g. osv-scanner) for a specific package version against affected semver/ecosystem ranges.
	VersionRate int

	// PackageRate is the sustained rate of POST /v1/query (package name only) requests per second.
	// It simulates unversioned queries retrieving all vulnerabilities associated with a given package.
	PackageRate int

	// PURLRate is the sustained rate of POST /v1/query (Package URL) requests per second.
	// It simulates queries using package URLs, randomly alternating between versioned and unversioned PURLs.
	PURLRate int

	// BatchRate is the sustained rate of POST /v1/querybatch requests per second.
	// Each batch request bundles up to MaxBatchQuerySize queries across all packages, simulating dependency manifest scans.
	BatchRate int

	// LargeBatchRate is the sustained rate of heavy POST /v1/querybatch requests per second.
	// Each request contains up to MaxLargeBatchQuerySize queries sampled strictly from the top 5,000 packages with the most vulnerabilities,
	// stress-testing backend range matching and result hydration under high match volumes.
	LargeBatchRate int

	// MaxBatchQuerySize is the maximum number of queries to bundle in a single standard /v1/querybatch request (1-1000).
	MaxBatchQuerySize int

	// MaxLargeBatchQuerySize is the maximum number of queries to bundle in a single heavy /v1/querybatch request (1-1000).
	MaxLargeBatchQuerySize int

	// StatsInterval is the interval at which progress and throughput statistics are logged.
	StatsInterval time.Duration
}

// DefaultGeneratorConfig returns standard load testing configuration matching production staging tests.
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		BaseURL:                "https://api.test.osv.dev/v1",
		Duration:               5 * time.Hour,
		VulnRate:               50,
		VersionRate:            80,
		PackageRate:            20,
		PURLRate:               30,
		BatchRate:              3,
		LargeBatchRate:         2,
		MaxBatchQuerySize:      100,
		MaxLargeBatchQuerySize: 100,
		StatsInterval:          30 * time.Second,
	}
}

// QueryPayload represents an individual query in OSV API.
type QueryPayload struct {
	Version string          `json:"version,omitempty"`
	Package *PackagePayload `json:"package,omitempty"`
}

// PackagePayload represents package identifier in OSV API query.
type PackagePayload struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// BatchQueryPayload represents payload for /v1/querybatch.
type BatchQueryPayload struct {
	Queries []QueryPayload `json:"queries"`
}

// GeneratorStats tracks request counts, outcomes, and latencies.
type GeneratorStats struct {
	TotalRequests     atomic.Uint64
	SuccessCount      atomic.Uint64
	ClientErrorCount  atomic.Uint64
	ServerErrorCount  atomic.Uint64
	NetworkErrorCount atomic.Uint64
	StartTime         time.Time
}

// NewGeneratorStats initializes a new statistics tracker.
func NewGeneratorStats() *GeneratorStats {
	return &GeneratorStats{
		StartTime: time.Now(),
	}
}

func (s *GeneratorStats) RecordStatus(code int) {
	s.TotalRequests.Add(1)
	if code >= 200 && code < 300 {
		s.SuccessCount.Add(1)
	} else if code >= 400 && code < 500 {
		s.ClientErrorCount.Add(1)
	} else {
		s.ServerErrorCount.Add(1)
	}
}

func (s *GeneratorStats) RecordNetworkError() {
	s.TotalRequests.Add(1)
	s.NetworkErrorCount.Add(1)
}

func (s *GeneratorStats) Summary() string {
	elapsed := time.Since(s.StartTime)
	total := s.TotalRequests.Load()
	success := s.SuccessCount.Load()
	clientErr := s.ClientErrorCount.Load()
	serverErr := s.ServerErrorCount.Load()
	netErr := s.NetworkErrorCount.Load()

	rps := 0.0
	if elapsed.Seconds() > 0 {
		rps = float64(total) / elapsed.Seconds()
	}

	return fmt.Sprintf("Elapsed: %s | Total: %d (%.1f req/s) | 2xx: %d | 4xx: %d | 5xx: %d | NetErr: %d",
		elapsed.Truncate(time.Second), total, rps, success, clientErr, serverErr, netErr)
}

// buildPackagePayload constructs payload for package query.
func buildPackagePayload(id string, vulnMap map[string]*SimpleVuln) ([]byte, error) {
	vuln, ok := vulnMap[id]
	if !ok {
		return nil, fmt.Errorf("vulnerability not found: %s", id)
	}

	return json.Marshal(QueryPayload{
		Package: &PackagePayload{
			Name:      vuln.Package,
			Ecosystem: vuln.Ecosystem,
		},
	})
}

// buildVersionPayload constructs payload for package version query.
func buildVersionPayload(id string, vulnMap map[string]*SimpleVuln) ([]byte, error) {
	vuln, ok := vulnMap[id]
	if !ok {
		return nil, fmt.Errorf("vulnerability not found: %s", id)
	}

	return json.Marshal(QueryPayload{
		Version: vuln.AffectedFuzzy,
		Package: &PackagePayload{
			Name:      vuln.Package,
			Ecosystem: vuln.Ecosystem,
		},
	})
}

// buildPURLPayload constructs payload for purl query.
func buildPURLPayload(rng *rand.Rand, id string, vulnMap map[string]*SimpleVuln) ([]byte, error) {
	vuln, ok := vulnMap[id]
	if !ok {
		return nil, fmt.Errorf("vulnerability not found: %s", id)
	}

	chosenPURL := vuln.PURL
	if rng.IntN(2) == 0 {
		chosenPURL = fmt.Sprintf("%s@%s", vuln.PURL, vuln.AffectedFuzzy)
	}

	return json.Marshal(QueryPayload{
		Package: &PackagePayload{
			PURL: chosenPURL,
		},
	})
}

// buildBatchPayload constructs payload for batch queries.
func buildBatchPayload(rng *rand.Rand, requestIDs []string, vulnMap map[string]*SimpleVuln, maxBatchQueries int) ([]byte, error) {
	if len(requestIDs) == 0 {
		return json.Marshal(BatchQueryPayload{Queries: []QueryPayload{}})
	}

	if maxBatchQueries <= 0 {
		maxBatchQueries = 100
	}

	sampleSize := min(rng.IntN(maxBatchQueries)+1, len(requestIDs))

	// Sample random IDs
	perm := rng.Perm(len(requestIDs))
	queries := make([]QueryPayload, 0, sampleSize)

	for i := range sampleSize {
		vulnID := requestIDs[perm[i]]
		vuln, ok := vulnMap[vulnID]
		if !ok {
			continue
		}

		queryType := rng.IntN(3)
		switch queryType {
		case 0: // version
			queries = append(queries, QueryPayload{
				Version: vuln.AffectedFuzzy,
				Package: &PackagePayload{
					Name:      vuln.Package,
					Ecosystem: vuln.Ecosystem,
				},
			})
		case 1: // package
			queries = append(queries, QueryPayload{
				Package: &PackagePayload{
					Name:      vuln.Package,
					Ecosystem: vuln.Ecosystem,
				},
			})
		case 2: // purl
			chosenPURL := vuln.PURL
			if rng.IntN(2) == 0 {
				chosenPURL = fmt.Sprintf("%s@%s", vuln.PURL, vuln.AffectedFuzzy)
			}
			queries = append(queries, QueryPayload{
				Package: &PackagePayload{
					PURL: chosenPURL,
				},
			})
		}
	}

	return json.Marshal(BatchQueryPayload{Queries: queries})
}

// newHTTPClient creates an HTTP client optimized for high concurrency load testing.
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2000,
		MaxIdleConnsPerHost:   1000,
		MaxConnsPerHost:       1000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   300 * time.Second,
	}
}

// executeRequest sends an HTTP request and updates stats.
func executeRequest(ctx context.Context, client *http.Client, req *http.Request, stats *GeneratorStats) {
	req = req.WithContext(ctx)
	resp, err := client.Do(req) // #nosec G704: Staging API load testing client
	if err != nil {
		if ctx.Err() == nil {
			logger.Warn("Failed to send HTTP request",
				"url", req.URL.String(),
				"method", req.Method,
				"error", err,
			)
		}
		stats.RecordNetworkError()

		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		logger.Warn("HTTP request returned error status",
			"url", req.URL.String(),
			"method", req.Method,
			"statusCode", resp.StatusCode,
			"response", string(bodySnippet),
		)
	}

	// Drain response body to enable connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	stats.RecordStatus(resp.StatusCode)
}

// runVulnWorker dispatches GET /v1/vulns/{id} requests evenly spaced at cfg.VulnRate per second.
func runVulnWorker(ctx context.Context, wg *sync.WaitGroup, client *http.Client, pools *QueryPools, stats *GeneratorStats, cfg GeneratorConfig) {
	if len(pools.VulnQueryIDs) == 0 || cfg.VulnRate <= 0 {
		return
	}

	ticker := time.NewTicker(time.Second / time.Duration(cfg.VulnRate))
	defer ticker.Stop()

	index := 0
	length := len(pools.VulnQueryIDs)
	baseURL := cfg.BaseURL + "/vulns"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reqID := pools.VulnQueryIDs[index%length]
			index++
			url := fmt.Sprintf("%s/%s", baseURL, reqID)
			//nolint:gosec // G704: Staging test generator
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			wg.Go(func() {
				executeRequest(ctx, client, req, stats)
			})
		}
	}
}

// runSingleQueryWorker dispatches POST /v1/query requests evenly spaced at the specified rate per second.
func runSingleQueryWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	client *http.Client,
	requestIDs []string,
	vulnMap map[string]*SimpleVuln,
	stats *GeneratorStats,
	rate int,
	cfg GeneratorConfig,
	payloadBuilder func(string, map[string]*SimpleVuln) ([]byte, error),
) {
	if len(requestIDs) == 0 || rate <= 0 {
		return
	}

	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	index := 0
	length := len(requestIDs)
	url := cfg.BaseURL + "/query"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reqID := requestIDs[index%length]
			index++
			payload, err := payloadBuilder(reqID, vulnMap)
			if err != nil {
				continue
			}
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			wg.Go(func() {
				executeRequest(ctx, client, req, stats)
			})
		}
	}
}

// runPURLWorker dispatches POST /v1/query (PURL) requests evenly spaced at cfg.PURLRate per second.
func runPURLWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	client *http.Client,
	requestIDs []string,
	vulnMap map[string]*SimpleVuln,
	stats *GeneratorStats,
	cfg GeneratorConfig,
	seed uint64,
) {
	if len(requestIDs) == 0 || cfg.PURLRate <= 0 {
		return
	}

	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(seed, seed^0x12345))
	ticker := time.NewTicker(time.Second / time.Duration(cfg.PURLRate))
	defer ticker.Stop()

	index := 0
	length := len(requestIDs)
	url := cfg.BaseURL + "/query"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reqID := requestIDs[index%length]
			index++
			payload, err := buildPURLPayload(rng, reqID, vulnMap)
			if err != nil {
				continue
			}
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			wg.Go(func() {
				executeRequest(ctx, client, req, stats)
			})
		}
	}
}

// runBatchWorker dispatches POST /v1/querybatch requests evenly spaced at the specified batchRate per second.
func runBatchWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	client *http.Client,
	requestIDs []string,
	vulnMap map[string]*SimpleVuln,
	stats *GeneratorStats,
	batchRate int,
	maxBatchQueries int,
	cfg GeneratorConfig,
	seed uint64,
) {
	if len(requestIDs) == 0 || batchRate <= 0 {
		return
	}

	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(seed, seed^0x6789A))
	ticker := time.NewTicker(time.Second / time.Duration(batchRate))
	defer ticker.Stop()

	url := cfg.BaseURL + "/querybatch"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payload, err := buildBatchPayload(rng, requestIDs, vulnMap, maxBatchQueries)
			if err != nil {
				continue
			}
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			wg.Go(func() {
				executeRequest(ctx, client, req, stats)
			})
		}
	}
}

// RunTrafficGenerator orchestrates concurrent traffic generation across all query types.
func RunTrafficGenerator(ctx context.Context, client *http.Client, pools *QueryPools, cfg GeneratorConfig, seed uint64) (*GeneratorStats, error) {
	if client == nil {
		client = newHTTPClient()
	}

	stats := NewGeneratorStats()

	logger.Info("Starting API traffic generator with smooth rate pacing",
		"baseURL", cfg.BaseURL,
		"duration", cfg.Duration,
		"vulnRate", cfg.VulnRate,
		"versionRate", cfg.VersionRate,
		"packageRate", cfg.PackageRate,
		"purlRate", cfg.PURLRate,
		"batchRate", cfg.BatchRate,
		"largeBatchRate", cfg.LargeBatchRate,
		"maxBatchQuerySize", cfg.MaxBatchQuerySize,
		"maxLargeBatchQuerySize", cfg.MaxLargeBatchQuerySize,
		"totalVulns", len(pools.VulnQueryIDs),
		"totalPackages", len(pools.PackageQueryIDs),
		"totalLargeBatchPackages", len(pools.LargeBatchQueryIDs),
	)

	genCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup

	// Start workers with smooth pacing and isolated rng seeds per worker
	wg.Go(func() {
		runVulnWorker(genCtx, &wg, client, pools, stats, cfg)
	})
	wg.Go(func() {
		runSingleQueryWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg.PackageRate, cfg, buildPackagePayload)
	})
	wg.Go(func() {
		runSingleQueryWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg.VersionRate, cfg, buildVersionPayload)
	})
	wg.Go(func() {
		runPURLWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg, seed+1)
	})
	wg.Go(func() {
		runBatchWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg.BatchRate, cfg.MaxBatchQuerySize, cfg, seed+2)
	})
	wg.Go(func() {
		runBatchWorker(genCtx, &wg, client, pools.LargeBatchQueryIDs, pools.VulnMap, stats, cfg.LargeBatchRate, cfg.MaxLargeBatchQuerySize, cfg, seed+3)
	})

	// Periodic stats reporter
	statsTicker := time.NewTicker(cfg.StatsInterval)
	defer statsTicker.Stop()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	for {
		select {
		case <-statsTicker.C:
			logger.Info("[Stats] " + stats.Summary())
		case <-doneCh:
			logger.Info("[Final Stats] " + stats.Summary())

			return stats, nil
		}
	}
}
