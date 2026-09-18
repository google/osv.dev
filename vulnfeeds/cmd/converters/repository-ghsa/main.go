// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main fetches GitHub repository-level security advisories and converts them to OSV format.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"golang.org/x/sync/semaphore"
)

var (
	reposFlag       = flag.String("repos", "", "Comma-separated list of GitHub repositories (e.g. owner/repo or https://github.com/owner/repo)")
	reposFileFlag   = flag.String("repos-file", "", "Path to a file containing a list of repositories, one per line")
	outDirFlag      = flag.String("out-dir", "output", "Directory to output converted OSV JSON files")
	gitterHostFlag  = flag.String("gitter-host", "", "URL of the Gitter caching service (defaults to GITTER_HOST env var)")
	githubTokenFlag = flag.String("github-token", "", "GitHub API token (defaults to GITHUB_TOKEN or GH_TOKEN env var)")
	stateFlag       = flag.String("state", "published", "Filter advisories by state (published, closed, withdrawn, or all)")
	workersFlag     = flag.Int("workers", 8, "Number of concurrent workers for processing repositories")
	uploadToGCSFlag = flag.Bool("upload-to-gcs", false, "Whether to upload output OSV records directly to Google Cloud Storage")
	outputBucket    = flag.String("output-bucket", "osv-test-cve-osv-conversion", "Destination GCS bucket name")
	gcsPrefix       = flag.String("gcs-prefix", "ghsa-repo-osv", "Prefix path in GCS bucket")
)

func main() {
	flag.Parse()

	logger.InitGlobalLogger()
	defer logger.Close()

	repos, err := collectRepos(*reposFlag, *reposFileFlag, flag.Args())
	if err != nil {
		logger.Fatal("Failed to collect repositories", slog.Any("error", err))
	}
	if len(repos) == 0 {
		logger.Fatal("No repositories specified. Use -repos, -repos-file, or positional arguments.")
	}

	// Configure Gitter host if specified via flag
	if *gitterHostFlag != "" {
		_ = os.Setenv("GITTER_HOST", *gitterHostFlag)
	}

	// Configure GitHub token
	token := *githubTokenFlag
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
	}

	if err := os.MkdirAll(*outDirFlag, 0755); err != nil {
		logger.Fatal("Failed to create output directory", slog.String("dir", *outDirFlag), slog.Any("error", err))
	}

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	ghClient := NewGitHubClient(token, httpClient)
	tagsCache := git.NewRepoTagsCache()

	var gcsHelper *gcs.Helper
	if *uploadToGCSFlag {
		var err error
		gcsHelper, err = gcs.InitUploadPool(context.Background(), *workersFlag, *outputBucket)
		if err != nil {
			logger.Fatal("Failed to initialize GCS helper", slog.String("bucket", *outputBucket), slog.Any("error", err))
		}
		defer gcsHelper.CloseAndWait()
	}

	processAllRepositories(context.Background(), repos, ghClient, tagsCache, httpClient, gcsHelper)
}

func collectRepos(reposCSV, reposFile string, positional []string) ([]string, error) {
	var list []string

	if reposCSV != "" {
		for _, r := range strings.Split(reposCSV, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				list = append(list, r)
			}
		}
	}

	if reposFile != "" {
		f, err := os.Open(reposFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open repos-file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				list = append(list, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed scanning repos-file: %w", err)
		}
	}

	for _, p := range positional {
		p = strings.TrimSpace(p)
		if p != "" {
			list = append(list, p)
		}
	}

	// Deduplicate repositories
	seen := make(map[string]bool)
	var deduped []string
	for _, r := range list {
		if !seen[r] {
			seen[r] = true
			deduped = append(deduped, r)
		}
	}

	return deduped, nil
}

func processAllRepositories(ctx context.Context, repos []string, ghClient *GitHubClient, tagsCache git.RepoTagsCache, httpClient *http.Client, gcsHelper *gcs.Helper) {
	numWorkers := *workersFlag
	if numWorkers <= 0 {
		numWorkers = 1
	}

	sem := semaphore.NewWeighted(int64(numWorkers))
	var wg sync.WaitGroup

	var (
		totalAdvisoriesCount atomic.Uint64
		successCount         atomic.Uint64
		failCount            atomic.Uint64
	)

	logger.Info("Starting processing repositories", slog.Int("repo_count", len(repos)), slog.Int("workers", numWorkers))

	for _, rawRepo := range repos {
		target, err := ParseRepoTarget(rawRepo)
		if err != nil {
			logger.Warn("Failed parsing repository identifier", slog.String("raw", rawRepo), slog.Any("error", err))
			failCount.Add(1)
			continue
		}

		if err := sem.Acquire(ctx, 1); err != nil {
			logger.Error("Context cancelled while acquiring semaphore", slog.Any("error", err))
			break
		}

		wg.Add(1)
		go func(t RepoTarget) {
			defer sem.Release(1)
			defer wg.Done()

			count, err := processRepository(ctx, t, ghClient, tagsCache, httpClient, gcsHelper)
			if err != nil {
				logger.Error("Failed processing repository", slog.String("repo", t.CanonicalURL), slog.Any("error", err))
				failCount.Add(1)
			} else {
				successCount.Add(1)
				totalAdvisoriesCount.Add(uint64(count))
			}
		}(target)
	}

	wg.Wait()

	logger.Info("Processing complete",
		slog.Uint64("successful_repos", successCount.Load()),
		slog.Uint64("failed_repos", failCount.Load()),
		slog.Uint64("total_advisories_converted", totalAdvisoriesCount.Load()),
	)
}

func processRepository(ctx context.Context, target RepoTarget, ghClient *GitHubClient, tagsCache git.RepoTagsCache, httpClient *http.Client, gcsHelper *gcs.Helper) (int, error) {
	logger.Info("Fetching advisories for repository", slog.String("owner", target.Owner), slog.String("repo", target.Repo))

	advisories, err := ghClient.FetchAdvisories(ctx, target.Owner, target.Repo, *stateFlag)
	if err != nil {
		return 0, fmt.Errorf("fetching advisories: %w", err)
	}

	if len(advisories) == 0 {
		logger.Info("No advisories found for repository", slog.String("repo", target.CanonicalURL))
		return 0, nil
	}

	logger.Info("Found advisories for repository", slog.String("repo", target.CanonicalURL), slog.Int("count", len(advisories)))

	// Fetch normalized Git tags for commit resolution
	normalizedTags, err := git.NormalizeRepoTags(target.CanonicalURL, tagsCache, httpClient)
	if err != nil {
		logger.Warn("Failed to normalize tags for repository; proceeding with partial commit resolution",
			slog.String("repo", target.CanonicalURL), slog.Any("error", err))
		normalizedTags = make(map[string]git.NormalizedTag)
	}

	convertedCount := 0
	for _, advisory := range advisories {
		vuln, err := ConvertAdvisoryToOSV(advisory, target, normalizedTags)
		if err != nil {
			logger.Warn("Failed converting advisory to OSV",
				slog.String("id", advisory.GHSAID), slog.String("repo", target.CanonicalURL), slog.Any("error", err))
			continue
		}

		if err := writeOSVRecord(vuln, *outDirFlag, gcsHelper, *gcsPrefix); err != nil {
			logger.Error("Failed writing OSV record",
				slog.String("id", advisory.GHSAID), slog.Any("error", err))
			continue
		}

		convertedCount++
	}

	return convertedCount, nil
}

func writeOSVRecord(vuln *vulns.Vulnerability, outDir string, gcsHelper *gcs.Helper, prefix string) error {
	vulnID := vuln.GetId()
	if vulnID == "" {
		return fmt.Errorf("vulnerability ID is empty")
	}

	var buf bytes.Buffer
	if err := vuln.ToJSON(&buf); err != nil {
		return fmt.Errorf("serializing vulnerability %s to JSON: %w", vulnID, err)
	}

	// Always write to local out-dir
	localPath := filepath.Join(outDir, fmt.Sprintf("%s.json", vulnID))
	if err := os.WriteFile(localPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("writing local file %s: %w", localPath, err)
	}

	// Upload to GCS if configured
	if gcsHelper != nil {
		gcsObjName := fmt.Sprintf("%s.json", vulnID)
		if prefix != "" {
			gcsObjName = fmt.Sprintf("%s/%s.json", strings.Trim(prefix, "/"), vulnID)
		}
		gcsHelper.Upload(gcsObjName, bytes.NewReader(buf.Bytes()), "", "application/json")
	}

	return nil
}
