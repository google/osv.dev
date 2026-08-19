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

// Package main downloads all machine-readable copyright files for packages in Debian unstable.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"cloud.google.com/go/storage"
	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/utility"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultFilelistURL      = "https://metadata.ftp-master.debian.org/changelogs/filelist.yaml.xz"
	DefaultURLBase          = "https://metadata.ftp-master.debian.org/changelogs"
	DefaultPrefixFilter     = "main/"
	DefaultMinExpectedFiles = 40000
	DefaultNumWorkers       = 50
	DefaultMaxFailureRate   = 0.05 // 5% maximum allowed failure rate
)

// ExtractUnstableCopyright parses Debian changelogs filelist YAML content from a reader
// and extracts the unstable_copyright path for each package matching the specified prefixFilter.
func ExtractUnstableCopyright(r io.Reader, prefixFilter string) ([]string, error) {
	scanner := bufio.NewScanner(r)
	const maxLineLen = 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxLineLen)

	var results []string
	inUnstable := false
	currentPkgFound := false

	for scanner.Scan() {
		line := scanner.Text()
		// Top-level package key: starts without whitespace and ends with colon
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(line, ":") {
			inUnstable = false
			currentPkgFound = false
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check if this is a suite/version subkey under the package
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "  -") && strings.HasSuffix(line, ":") {
			if trimmed == "unstable:" || trimmed == "'unstable':" || trimmed == `"unstable":` {
				inUnstable = true
			} else {
				inUnstable = false
			}
			continue
		}

		// If we are within the "unstable" section and haven't found a copyright file for this package yet
		if inUnstable && !currentPkgFound && strings.HasPrefix(trimmed, "- ") {
			entry := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			entry = strings.Trim(entry, `"'`)
			if strings.HasSuffix(entry, "unstable_copyright") {
				if prefixFilter == "" || strings.HasPrefix(entry, prefixFilter) {
					results = append(results, entry)
				}
				currentPkgFound = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning filelist YAML: %w", err)
	}

	return results, nil
}

// DownloadFilesConcurrently downloads all files in filelist using a channel-based worker pool.
func DownloadFilesConcurrently(ctx context.Context, client *http.Client, filelist []string, urlBase, workDir string, numWorkers int, skipExisting bool, maxFailureRate float64) error {
	if numWorkers <= 0 {
		numWorkers = DefaultNumWorkers
	}

	total := len(filelist)
	logger.Info("Starting concurrent download of copyright files",
		slog.Int("total_files", total),
		slog.Int("workers", numWorkers),
		slog.Bool("skip_existing", skipExisting),
	)

	jobs := make(chan string, numWorkers*2)
	var completed atomic.Int64
	var failed atomic.Int64
	var skipped atomic.Int64
	startTime := time.Now()

	g, ctx := errgroup.WithContext(ctx)

	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for path := range jobs {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(urlBase, "/"), strings.TrimLeft(path, "/"))
				destPath := filepath.Join(workDir, path)

				if skipExisting {
					if fi, err := os.Stat(destPath); err == nil && fi.Size() > 0 {
						skipped.Add(1)
						count := completed.Add(1)
						logProgress(count, total, startTime)
						continue
					}
				}

				if err := utility.DownloadFile(ctx, client, fullURL, destPath, false); err != nil {
					failed.Add(1)
					logger.Warn("Failed to download copyright file", slog.String("url", fullURL), slog.Any("err", err))
				} else {
					count := completed.Add(1)
					logProgress(count, total, startTime)
				}
			}
			return nil
		})
	}

	go func() {
		defer close(jobs)
		for _, path := range filelist {
			select {
			case <-ctx.Done():
				return
			case jobs <- path:
			}
		}
	}()

	if err := g.Wait(); err != nil {
		return fmt.Errorf("concurrent download aborted: %w", err)
	}

	completedCount := completed.Load()
	failedCount := failed.Load()
	skippedCount := skipped.Load()

	logger.Info("Finished downloading copyright files",
		slog.Int64("completed", completedCount),
		slog.Int64("failed", failedCount),
		slog.Int64("skipped", skippedCount),
		slog.Int("total", total),
		slog.Duration("elapsed", time.Since(startTime)),
	)

	if total > 0 {
		failRatio := float64(failedCount) / float64(total)
		if failRatio > maxFailureRate || (completedCount == 0 && total > 0) {
			return fmt.Errorf("too many downloads failed: %d/%d (%.2f%% failed, max threshold is %.2f%%)",
				failedCount, total, failRatio*100.0, maxFailureRate*100.0)
		}
	}

	return nil
}

func logProgress(count int64, total int, startTime time.Time) {
	if count%5000 == 0 || count == int64(total) {
		pct := float64(count) / float64(total) * 100.0
		logger.Info("Download progress",
			slog.Int64("completed", count),
			slog.Int("total", total),
			slog.Float64("percent", pct),
			slog.Duration("elapsed", time.Since(startTime)),
		)
	}
}

// GenerateCurlConfiguration generates a curl config file for parallel downloads.
func GenerateCurlConfiguration(filelist []string, urlBase, configPath string) error {
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create curl config file: %w", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, path := range filelist {
		fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(urlBase, "/"), strings.TrimLeft(path, "/"))
		if _, err := fmt.Fprintf(w, "--output %s\nurl = %s\n", path, fullURL); err != nil {
			return fmt.Errorf("failed to write curl config entry: %w", err)
		}
	}

	return w.Flush()
}

// ExecuteCurl runs curl with the specified configuration file in the working directory.
func ExecuteCurl(ctx context.Context, configPath, workDir string) error {
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	cmd := exec.CommandContext(ctx, "curl", "--parallel", "--create-dirs", "--config", configPath)
	cmd.Dir = workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Info("Executing curl in parallel", slog.String("config", configPath), slog.String("workDir", workDir))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("curl execution failed: %w", err)
	}

	return nil
}

// UploadTarToGCS creates a tar archive of workDir and streams it directly to GCS.
func UploadTarToGCS(ctx context.Context, storageClient *storage.Client, workDir, gcsURI string) error {
	bucketName, objectName, err := gcs.ParseGCSPath(gcsURI)
	if err != nil {
		return err
	}

	logger.Info("Streaming tar archive to GCS", slog.String("bucket", bucketName), slog.String("object", objectName), slog.String("workDir", workDir))
	bkt := storageClient.Bucket(bucketName)

	pipeReader, pipeWriter := io.Pipe()
	errChan := make(chan error, 1)

	go func() {
		err := utility.CreateTarArchive(workDir, pipeWriter)
		_ = pipeWriter.CloseWithError(err)
		errChan <- err
	}()

	uploadErr := gcs.UploadToGCS(ctx, bkt, objectName, pipeReader, "application/x-tar", nil)
	archiveErr := <-errChan

	if uploadErr != nil {
		return fmt.Errorf("failed to upload tar to GCS %s: %w", gcsURI, uploadErr)
	}
	if archiveErr != nil {
		return fmt.Errorf("failed to create tar archive: %w", archiveErr)
	}

	logger.Info("Successfully uploaded tar archive to GCS", slog.String("gcsURI", gcsURI))
	return nil
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	workDirFlag := flag.String("work-dir", "", "Directory to download copyright files into.")
	filelistURL := flag.String("filelist-url", DefaultFilelistURL, "URL of the Debian filelist.yaml.xz file.")
	urlBase := flag.String("url-base", DefaultURLBase, "Base URL for downloading Debian changelog/copyright files.")
	prefixFilter := flag.String("prefix-filter", DefaultPrefixFilter, "Prefix filter for package paths to download (e.g. 'main/').")
	minExpectedFiles := flag.Int("min-expected-files", DefaultMinExpectedFiles, "Minimum expected number of copyright files.")
	numWorkers := flag.Int("workers", DefaultNumWorkers, "Number of concurrent download workers.")
	skipExisting := flag.Bool("skip-existing", false, "Skip downloading files that already exist on disk with non-zero size.")
	maxFailureRate := flag.Float64("max-failure-rate", DefaultMaxFailureRate, "Maximum allowable fraction of failed downloads before failing the job.")
	gcsPath := flag.String("gcs-path", "", "Destination GCS path for tarball archive (e.g. gs://bucket/path/debian_copyright.tar). Defaults to GCS_PATH env var if unset.")
	tarPath := flag.String("tar-path", "", "Optional local destination path for tarball archive (e.g. /scratch/debian_copyright.tar).")
	useCurl := flag.Bool("use-curl", false, "If true, delegate downloads to curl --parallel instead of Go HTTP workers.")
	curlConfigFile := flag.String("curl-config-file", "", "Optional path to write the generated curl configuration to.")
	curlConfigOnly := flag.Bool("curl-config-only", false, "If true, only write the curl configuration file and exit.")

	flag.Parse()

	workDir := *workDirFlag
	if workDir == "" && flag.NArg() > 0 {
		workDir = flag.Arg(0)
	}
	if workDir == "" {
		workDir = "."
	}

	ctx := context.Background()

	poolSize := *numWorkers * 2
	if poolSize < 100 {
		poolSize = 100
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        poolSize,
			MaxIdleConnsPerHost: poolSize,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}

	logger.Info("Streaming and decompressing filelist", slog.String("url", *filelistURL))
	decompressedReader, err := utility.FetchAndDecompressXZ(ctx, httpClient, *filelistURL)
	if err != nil {
		logger.Fatal("Failed to fetch and decompress filelist", slog.Any("err", err))
	}
	defer decompressedReader.Close()

	logger.Info("Extracting unstable copyright file paths", slog.String("prefixFilter", *prefixFilter))
	copyrightFiles, err := ExtractUnstableCopyright(decompressedReader, *prefixFilter)
	if err != nil {
		logger.Fatal("Failed to extract unstable copyright paths", slog.Any("err", err))
	}
	_ = decompressedReader.Close()

	logger.Info("Discovered copyright files", slog.Int("count", len(copyrightFiles)))

	if len(copyrightFiles) < *minExpectedFiles {
		logger.Fatal("Unexpectedly small number of copyright files found",
			slog.Int("found", len(copyrightFiles)),
			slog.Int("min_expected", *minExpectedFiles),
		)
	}

	if *useCurl || *curlConfigOnly || *curlConfigFile != "" {
		cfgPath := *curlConfigFile
		if cfgPath == "" {
			tempDir, err := os.MkdirTemp("", "debian-copyright-mirror-curl-*")
			if err != nil {
				logger.Fatal("Failed to create temporary directory for curl config", slog.Any("err", err))
			}
			defer os.RemoveAll(tempDir)
			cfgPath = filepath.Join(tempDir, "curl_configuration")
		}

		logger.Info("Generating curl configuration", slog.String("path", cfgPath))
		if err := GenerateCurlConfiguration(copyrightFiles, *urlBase, cfgPath); err != nil {
			logger.Fatal("Failed to generate curl configuration", slog.Any("err", err))
		}

		if *curlConfigOnly {
			logger.Info("Curl configuration generated successfully; exiting as requested.")
			return
		}

		if *useCurl {
			if err := ExecuteCurl(ctx, cfgPath, workDir); err != nil {
				logger.Fatal("Curl download failed", slog.Any("err", err))
			}
		}
	} else {
		if err := DownloadFilesConcurrently(ctx, httpClient, copyrightFiles, *urlBase, workDir, *numWorkers, *skipExisting, *maxFailureRate); err != nil {
			logger.Fatal("Concurrent download failed", slog.Any("err", err))
		}
	}

	if *tarPath != "" {
		logger.Info("Creating local tar archive", slog.String("path", *tarPath), slog.String("workDir", workDir))
		if err := os.MkdirAll(filepath.Dir(*tarPath), 0755); err != nil {
			logger.Fatal("Failed to create tar destination directory", slog.Any("err", err))
		}
		tarFile, err := os.Create(*tarPath)
		if err != nil {
			logger.Fatal("Failed to create tar file", slog.Any("err", err))
		}
		if err := utility.CreateTarArchive(workDir, tarFile); err != nil {
			_ = tarFile.Close()
			logger.Fatal("Failed to write tar archive", slog.Any("err", err))
		}
		if err := tarFile.Close(); err != nil {
			logger.Fatal("Failed to close tar file", slog.Any("err", err))
		}
		logger.Info("Successfully created local tar archive", slog.String("path", *tarPath))
	}

	gcsDest := *gcsPath
	if gcsDest == "" {
		gcsDest = os.Getenv("GCS_PATH")
	}
	if gcsDest != "" {
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create GCS client", slog.Any("err", err))
		}
		defer storageClient.Close()

		if err := UploadTarToGCS(ctx, storageClient, workDir, gcsDest); err != nil {
			logger.Fatal("Failed to upload tar archive to GCS", slog.Any("err", err))
		}
	}

	logger.Info("Debian copyright mirror sync completed successfully.", slog.String("workDir", workDir))
}
