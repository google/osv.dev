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
	BaseURL        string
	Duration       time.Duration
	Interval       time.Duration
	VulnRate       int
	VersionRate    int
	PackageRate    int
	PURLRate       int
	BatchRate      int
	LargeBatchRate int
	StatsInterval  time.Duration
}

// DefaultGeneratorConfig returns standard load testing configuration matching production staging tests.
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		BaseURL:        "https://api.test.osv.dev/v1",
		Duration:       5 * time.Hour,
		Interval:       1 * time.Second,
		VulnRate:       50,
		VersionRate:    80,
		PackageRate:    20,
		PURLRate:       30,
		BatchRate:      3,
		LargeBatchRate: 2,
		StatsInterval:  30 * time.Second,
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
func buildBatchPayload(rng *rand.Rand, requestIDs []string, vulnMap map[string]*SimpleVuln) ([]byte, error) {
	if len(requestIDs) == 0 {
		return json.Marshal(BatchQueryPayload{Queries: []QueryPayload{}})
	}

	sampleSize := rng.IntN(100) + 1
	if sampleSize > len(requestIDs) {
		sampleSize = len(requestIDs)
	}

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
	resp, err := client.Do(req)
	if err != nil {
		stats.RecordNetworkError()

		return
	}
	defer resp.Body.Close()

	// Drain response body to enable connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	stats.RecordStatus(resp.StatusCode)
}

// runVulnWorker sends GET /v1/vulns/{id} requests.
func runVulnWorker(ctx context.Context, wg *sync.WaitGroup, client *http.Client, pools *QueryPools, stats *GeneratorStats, cfg GeneratorConfig) {
	if len(pools.VulnQueryIDs) == 0 || cfg.VulnRate <= 0 {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	index := 0
	length := len(pools.VulnQueryIDs)
	baseURL := cfg.BaseURL + "/vulns"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := range cfg.VulnRate {
				reqID := pools.VulnQueryIDs[(index+i)%length]
				url := fmt.Sprintf("%s/%s", baseURL, reqID)
				req, err := http.NewRequest(http.MethodGet, url, nil)
				if err != nil {
					continue
				}
				wg.Go(func() {
					executeRequest(ctx, client, req, stats)
				})
			}
			index = (index + cfg.VulnRate) % length
		}
	}
}

// runSingleQueryWorker sends POST /v1/query requests using the given payload builder.
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

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	index := 0
	length := len(requestIDs)
	url := cfg.BaseURL + "/query"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := range rate {
				reqID := requestIDs[(index+i)%length]
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
			index = (index + rate) % length
		}
	}
}

// runPURLWorker sends POST /v1/query requests with purl payload.
func runPURLWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	client *http.Client,
	requestIDs []string,
	vulnMap map[string]*SimpleVuln,
	stats *GeneratorStats,
	cfg GeneratorConfig,
	rng *rand.Rand,
) {
	if len(requestIDs) == 0 || cfg.PURLRate <= 0 {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	index := 0
	length := len(requestIDs)
	url := cfg.BaseURL + "/query"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := range cfg.PURLRate {
				reqID := requestIDs[(index+i)%length]
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
			index = (index + cfg.PURLRate) % length
		}
	}
}

// runBatchWorker sends POST /v1/querybatch requests.
func runBatchWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	client *http.Client,
	requestIDs []string,
	vulnMap map[string]*SimpleVuln,
	stats *GeneratorStats,
	batchRate int,
	cfg GeneratorConfig,
	rng *rand.Rand,
) {
	if len(requestIDs) == 0 || batchRate <= 0 {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	url := cfg.BaseURL + "/querybatch"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for range batchRate {
				payload, err := buildBatchPayload(rng, requestIDs, vulnMap)
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
}

// RunTrafficGenerator orchestrates concurrent traffic generation across all query types.
func RunTrafficGenerator(ctx context.Context, client *http.Client, pools *QueryPools, cfg GeneratorConfig, seed uint64) (*GeneratorStats, error) {
	if client == nil {
		client = newHTTPClient()
	}

	stats := NewGeneratorStats()
	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(seed, seed^0x5DEECE66D))

	logger.Info("Starting API traffic generator",
		"baseURL", cfg.BaseURL,
		"duration", cfg.Duration,
		"vulnRate", cfg.VulnRate,
		"versionRate", cfg.VersionRate,
		"packageRate", cfg.PackageRate,
		"purlRate", cfg.PURLRate,
		"batchRate", cfg.BatchRate,
		"largeBatchRate", cfg.LargeBatchRate,
		"totalVulns", len(pools.VulnQueryIDs),
		"totalPackages", len(pools.PackageQueryIDs),
		"totalLargeBatchPackages", len(pools.LargeBatchQueryIDs),
	)

	genCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup

	// Start workers
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
		runPURLWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg, rng)
	})
	wg.Go(func() {
		runBatchWorker(genCtx, &wg, client, pools.PackageQueryIDs, pools.VulnMap, stats, cfg.BatchRate, cfg, rng)
	})
	wg.Go(func() {
		runBatchWorker(genCtx, &wg, client, pools.LargeBatchQueryIDs, pools.VulnMap, stats, cfg.LargeBatchRate, cfg, rng)
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
