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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/storage"
	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"golang.org/x/sync/semaphore"
)

var (
	reposFlag            = flag.String("repos", "", "Comma-separated list of GitHub repositories (e.g. owner/repo or https://github.com/owner/repo)")
	reposFileFlag        = flag.String("repos-file", "", "Path to a file (or gs://bucket/path.json) containing repositories")
	reposGCSPathFlag     = flag.String("repos-gcs-path", "", "Google Cloud Storage URI (gs://bucket/path.json) containing repository list")
	outDirFlag           = flag.String("out-dir", "output", "Directory to output converted OSV JSON files")
	gitterHostFlag       = flag.String("gitter-host", "", "URL of the Gitter caching service (defaults to GITTER_HOST env var)")
	githubTokenFlag      = flag.String("github-token", "", "GitHub API token (defaults to GITHUB_TOKEN or GH_TOKEN env var)")
	stateFlag            = flag.String("state", "published", "Filter advisories by state (published, closed, withdrawn, or all)")
	workersFlag          = flag.Int("workers", 8, "Number of concurrent workers for processing repositories")
	uploadToGCSFlag      = flag.Bool("upload-to-gcs", false, "Whether to upload output OSV records directly to Google Cloud Storage")
	outputBucketFlag     = flag.String("output-bucket", "", "Destination GCS bucket name (defaults to OUTPUT_GCS_BUCKET or OUTPUT_BUCKET env var)")
	gcsPrefixFlag        = flag.String("gcs-prefix", "ghsa-repo-osv", "Prefix path in GCS bucket")
	datastoreProjectFlag = flag.String("datastore-project", "", "Google Cloud project ID for Datastore JobData tracking (defaults to GOOGLE_CLOUD_PROJECT or DATASTORE_PROJECT_ID env var)")
	datastoreJobIDFlag   = flag.String("datastore-job-id", defaultJobDataKey, "Entity ID in Datastore JobData kind")
	saveLastRunFlag      = flag.Bool("save-last-run", false, "Whether to record last_run_time in Datastore upon successful completion")
)

func main() {
	flag.Parse()

	logger.InitGlobalLogger()
	defer logger.Close()

	ctx := context.Background()

	var storageClient *storage.Client
	defer func() {
		if storageClient != nil {
			_ = storageClient.Close()
		}
	}()

	repos, err := collectRepos(ctx, *reposFlag, *reposFileFlag, *reposGCSPathFlag, flag.Args(), storageClient)
	if err != nil {
		logger.Fatal("Failed to collect repositories", slog.Any("error", err))
	}
	if len(repos) == 0 {
		logger.Fatal("No repositories specified. Use -repos, -repos-file, -repos-gcs-path, or positional arguments.")
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

	if *outDirFlag != "" {
		if err := os.MkdirAll(*outDirFlag, 0755); err != nil {
			logger.Fatal("Failed to create output directory", slog.String("dir", *outDirFlag), slog.Any("error", err))
		}
	}

	// Configure GCS Upload
	uploadToGCS := *uploadToGCSFlag
	if !uploadToGCS && os.Getenv("UPLOAD_TO_GCS") == "true" {
		uploadToGCS = true
	}

	bucketName := *outputBucketFlag
	if bucketName == "" {
		bucketName = os.Getenv("OUTPUT_GCS_BUCKET")
		if bucketName == "" {
			bucketName = os.Getenv("OUTPUT_BUCKET")
			if bucketName == "" {
				bucketName = "osv-test-ghsa-repo-conversion"
			}
		}
	}

	var gcsHelper *gcs.Helper
	if uploadToGCS {
		var err error
		gcsHelper, err = gcs.InitUploadPool(ctx, *workersFlag, bucketName)
		if err != nil {
			logger.Fatal("Failed to initialize GCS helper", slog.String("bucket", bucketName), slog.Any("error", err))
		}
		defer gcsHelper.CloseAndWait()
	}

	// Configure Datastore JobData tracking
	dsProject := *datastoreProjectFlag
	if dsProject == "" {
		dsProject = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if dsProject == "" {
			dsProject = os.Getenv("DATASTORE_PROJECT_ID")
		}
	}

	var jobStore JobDataStore
	shouldSaveLastRun := *saveLastRunFlag || (dsProject != "" && *datastoreProjectFlag != "")
	if dsProject != "" {
		var err error
		jobStore, err = NewDatastoreJobStore(ctx, dsProject)
		if err != nil {
			logger.Warn("Failed to initialize Datastore client for JobData tracking", slog.String("project", dsProject), slog.Any("error", err))
		} else {
			defer jobStore.Close()
			if lastRun, err := jobStore.GetLastRun(ctx, *datastoreJobIDFlag); err == nil && lastRun != nil {
				logger.Info("Previous job run time retrieved from Datastore", slog.String("job_id", *datastoreJobIDFlag), slog.Time("last_run", *lastRun))
			}
		}
	}

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	ghClient := NewGitHubClient(token, httpClient)
	tagsCache := git.NewRepoTagsCache()

	processAllRepositories(ctx, repos, ghClient, tagsCache, httpClient, gcsHelper)

	// Record execution timestamp in Datastore upon completion
	if shouldSaveLastRun && jobStore != nil {
		now := time.Now().UTC()
		if err := jobStore.SetLastRun(ctx, *datastoreJobIDFlag, now); err != nil {
			logger.Error("Failed to save last_run_time in Datastore", slog.String("job_id", *datastoreJobIDFlag), slog.Any("error", err))
		} else {
			logger.Info("Successfully saved last_run_time to Datastore", slog.String("job_id", *datastoreJobIDFlag), slog.Time("timestamp", now))
		}
	}
}

// parseRepoFile parses repository identifiers from raw bytes supporting JSON arrays of strings,
// JSON arrays of objects with repo keys, JSON maps/dictionaries, and plain newline-delimited text.
func parseRepoFile(data []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// If data starts with [ or {, attempt JSON parsing
	if trimmed[0] == '[' || trimmed[0] == '{' {
		// 1. Try []string
		var strList []string
		if err := json.Unmarshal(trimmed, &strList); err == nil {
			var result []string
			for _, s := range strList {
				s = strings.TrimSpace(s)
				if s != "" {
					result = append(result, s)
				}
			}

			return result, nil
		}

		// 2. Try []map[string]any
		var objList []map[string]any
		if err := json.Unmarshal(trimmed, &objList); err == nil {
			var result []string
			for _, obj := range objList {
				if r := extractRepoFromMap(obj); r != "" {
					result = append(result, r)
				}
			}
			if len(result) > 0 {
				return result, nil
			}
		}

		// 3. Try map[string]json.RawMessage
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err == nil {
			// Check for wrapper keys like "repos", "repositories", "items", "data"
			for _, key := range []string{"repos", "repositories", "items", "data"} {
				if raw, ok := rawMap[key]; ok {
					subList, err := parseRepoFile(raw)
					if err == nil && len(subList) > 0 {
						return subList, nil
					}
				}
			}

			// If no known wrapper key, keys themselves might be repo names (e.g. owner/repo)
			var result []string
			for k := range rawMap {
				k = strings.TrimSpace(k)
				if strings.Contains(k, "/") {
					result = append(result, k)
				}
			}
			if len(result) > 0 {
				return result, nil
			}
		}
	}

	// Fallback to line-by-line plain text scanning
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	var result []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading plain text repo list: %w", err)
	}

	return result, nil
}

func extractRepoFromMap(m map[string]any) string {
	candidateKeys := []string{"repo", "url", "name", "repository", "canonical_url", "git"}
	for _, k := range candidateKeys {
		if val, ok := m[k]; ok {
			if s, ok := val.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					return s
				}
			}
		}
	}

	return ""
}

// readRepoFile reads repository identifiers from either a local file or a Google Cloud Storage URI (gs://bucket/object).
func readRepoFile(ctx context.Context, pathStr string, gcsClient *storage.Client) ([]string, error) {
	if u, ok := strings.CutPrefix(pathStr, "gs://"); ok {
		parts := strings.SplitN(u, "/", 2)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid GCS path %q: must be in format gs://bucket/object", pathStr)
		}
		bucketName := parts[0]
		objectName := parts[1]

		clientToUse := gcsClient
		var createdClient bool
		if clientToUse == nil {
			var err error
			clientToUse, err = storage.NewClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("creating GCS client for %s: %w", pathStr, err)
			}
			createdClient = true
		}
		if createdClient {
			defer clientToUse.Close()
		}

		rc, err := clientToUse.Bucket(bucketName).Object(objectName).NewReader(ctx)
		if err != nil {
			return nil, fmt.Errorf("opening GCS object %s: %w", pathStr, err)
		}
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("reading GCS object %s: %w", pathStr, err)
		}

		return parseRepoFile(data)
	}

	data, err := os.ReadFile(pathStr)
	if err != nil {
		return nil, fmt.Errorf("reading local file %s: %w", pathStr, err)
	}

	return parseRepoFile(data)
}

func collectRepos(ctx context.Context, reposCSV, reposFile, reposGCSPath string, positional []string, gcsClient *storage.Client) ([]string, error) {
	var list []string

	if reposCSV != "" {
		for r := range strings.SplitSeq(reposCSV, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				list = append(list, r)
			}
		}
	}

	if reposGCSPath != "" {
		gcsList, err := readRepoFile(ctx, reposGCSPath, gcsClient)
		if err != nil {
			return nil, fmt.Errorf("failed to read repos from GCS path %s: %w", reposGCSPath, err)
		}
		list = append(list, gcsList...)
	}

	if reposFile != "" {
		fileList, err := readRepoFile(ctx, reposFile, gcsClient)
		if err != nil {
			return nil, fmt.Errorf("failed to read repos from repos-file %s: %w", reposFile, err)
		}
		list = append(list, fileList...)
	}

	for _, p := range positional {
		p = strings.TrimSpace(p)
		if p != "" {
			list = append(list, p)
		}
	}

	// Deduplicate repositories preserving order
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
	//nolint:contextcheck // git.NormalizeRepoTags does not accept a Context parameter.
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

		if err := writeOSVRecord(vuln, *outDirFlag, gcsHelper, *gcsPrefixFlag); err != nil {
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
		return errors.New("vulnerability ID is empty")
	}

	var buf bytes.Buffer
	if err := vuln.ToJSON(&buf); err != nil {
		return fmt.Errorf("serializing vulnerability %s to JSON: %w", vulnID, err)
	}

	// Write to local out-dir if provided
	if outDir != "" {
		localPath := filepath.Join(outDir, vulnID+".json")
		if err := os.WriteFile(localPath, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("writing local file %s: %w", localPath, err)
		}
	}

	// Upload to GCS if configured
	if gcsHelper != nil {
		gcsObjName := vulnID + ".json"
		if prefix != "" {
			gcsObjName = strings.Trim(prefix, "/") + "/" + vulnID + ".json"
		}
		hash := sha256.Sum256(buf.Bytes())
		hexHash := hex.EncodeToString(hash[:])
		gcsHelper.Upload(gcsObjName, bytes.NewReader(buf.Bytes()), hexHash, "application/json")
	}

	return nil
}
