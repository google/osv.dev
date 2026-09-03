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

	"cloud.google.com/go/storage"
	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
)

const (
	DefaultFilelistURL      = "https://metadata.ftp-master.debian.org/changelogs/filelist.yaml.xz"
	DefaultURLBase          = "https://metadata.ftp-master.debian.org/changelogs"
	DefaultPrefixFilter     = "main/"
	DefaultMinExpectedFiles = 40000
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
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(line, ":") {
			inUnstable = false
			currentPkgFound = false

			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "  -") && strings.HasSuffix(line, ":") {
			inUnstable = trimmed == "unstable:" || trimmed == "'unstable':" || trimmed == `"unstable":`

			continue
		}

		if inUnstable && !currentPkgFound && strings.HasPrefix(trimmed, "- ") {
			entry := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")), `"'`)
			if strings.HasSuffix(entry, "unstable_copyright") && (prefixFilter == "" || strings.HasPrefix(entry, prefixFilter)) {
				results = append(results, entry)
				currentPkgFound = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning filelist YAML: %w", err)
	}

	return results, nil
}

func fetchCopyrightFiles(ctx context.Context, filelistURL, prefixFilter string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, filelistURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, filelistURL)
	}

	cmd := exec.CommandContext(ctx, "xz", "-dc")
	cmd.Stdin = resp.Body
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	files, err := ExtractUnstableCopyright(stdout, prefixFilter)
	_ = cmd.Wait()

	return files, err
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

// CreateTarArchive creates a tar archive of workDir using the system tar command.
func CreateTarArchive(ctx context.Context, workDir, tarPath string) error {
	// #nosec G204 -- arguments are locally configured paths
	cmd := exec.CommandContext(ctx, "tar", "-C", workDir, "--exclude="+filepath.Base(tarPath), "-cf", tarPath, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logger.Info("Creating tar archive", slog.String("workDir", workDir), slog.String("tarPath", tarPath))

	return cmd.Run()
}

func uploadToGCS(ctx context.Context, tarPath, gcsURI string) error {
	bucketName, objectName, err := gcs.ParseGCSPath(gcsURI)
	if err != nil {
		return err
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	logger.Info("Uploading tar archive to GCS", slog.String("bucket", bucketName), slog.String("object", objectName))

	return gcs.UploadFile(ctx, client.Bucket(bucketName), objectName, tarPath)
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	filelistURL := flag.String("filelist-url", DefaultFilelistURL, "URL of the Debian filelist.yaml.xz file.")
	urlBase := flag.String("url-base", DefaultURLBase, "Base URL for downloading Debian changelog/copyright files.")
	prefixFilter := flag.String("prefix-filter", DefaultPrefixFilter, "Prefix filter for package paths to download (e.g. 'main/').")
	minExpectedFiles := flag.Int("min-expected-files", DefaultMinExpectedFiles, "Minimum expected number of copyright files.")
	outDirFlag := flag.String("out-dir", "", "Directory to download copyright files into (defaults to WORK_DIR env var or ./debian_copyright).")
	workDirFlag := flag.String("work-dir", "", "Alias for -out-dir.")
	tarPathFlag := flag.String("tar-path", "", "Optional local destination path for tarball archive.")
	gcsPathFlag := flag.String("gcs-path", "", "Destination GCS path for tarball archive (defaults to GCS_PATH env var).")

	flag.Parse()

	workDir := *outDirFlag
	if *workDirFlag != "" {
		workDir = *workDirFlag
	} else if flag.NArg() > 0 {
		workDir = flag.Arg(0)
	} else if workDir == "" {
		if envWorkDir := os.Getenv("WORK_DIR"); envWorkDir != "" {
			workDir = envWorkDir
		} else {
			workDir = "debian_copyright"
		}
	}
	workDir = filepath.Clean(workDir)

	ctx := context.Background()

	logger.Info("Fetching and extracting copyright filelist", slog.String("url", *filelistURL))
	copyrightFiles, err := fetchCopyrightFiles(ctx, *filelistURL, *prefixFilter)
	if err != nil {
		logger.Fatal("Failed to obtain copyright file list", slog.Any("err", err))
	}

	logger.Info("Discovered copyright files", slog.Int("count", len(copyrightFiles)))
	if len(copyrightFiles) < *minExpectedFiles {
		logger.Fatal("Unexpectedly small number of copyright files found",
			slog.Int("found", len(copyrightFiles)),
			slog.Int("min_expected", *minExpectedFiles),
		)
	}

	tempDir, err := os.MkdirTemp("", "debian-copyright-mirror-*")
	if err != nil {
		logger.Fatal("Failed to create temp dir", slog.Any("err", err))
	}
	defer os.RemoveAll(tempDir)

	cfgPath := filepath.Join(tempDir, "curl_configuration")
	if err := GenerateCurlConfiguration(copyrightFiles, *urlBase, cfgPath); err != nil {
		logger.Fatal("Failed to generate curl configuration", slog.Any("err", err))
	}

	if err := ExecuteCurl(ctx, cfgPath, workDir); err != nil {
		logger.Fatal("Curl download failed", slog.Any("err", err))
	}

	gcsDest := *gcsPathFlag
	if gcsDest == "" {
		gcsDest = os.Getenv("GCS_PATH")
	}

	tarDest := *tarPathFlag
	if tarDest == "" && gcsDest != "" {
		tarDest = filepath.Join(workDir, filepath.Base(gcsDest))
	}

	if tarDest != "" {
		if err := CreateTarArchive(ctx, workDir, tarDest); err != nil {
			logger.Fatal("Failed to create tar archive", slog.Any("err", err))
		}
		if gcsDest != "" {
			if err := uploadToGCS(ctx, tarDest, gcsDest); err != nil {
				logger.Fatal("Failed to upload tar archive to GCS", slog.Any("err", err))
			}
		}
	}

	logger.Info("Debian copyright mirror sync completed successfully.", slog.String("workDir", workDir))
}
