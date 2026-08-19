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

package utility

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sethvargo/go-retry"
)

const (
	DefaultDownloadTimeout = 30 * time.Second
)

// DownloadFile downloads a URL to a local destination file with automatic retries,
// safe temporary file writing, and on-demand directory creation.
// If skipExisting is true and destPath exists with non-zero size, the download is skipped.
func DownloadFile(ctx context.Context, client *http.Client, url, destPath string, skipExisting bool) error {
	if skipExisting {
		if fi, err := os.Stat(destPath); err == nil && fi.Size() > 0 {
			return nil
		}
	}

	backoff := retry.NewExponential(1 * time.Second)
	backoff = retry.WithMaxRetries(3, backoff)

	return retry.Do(ctx, backoff, func(ctx context.Context) error {
		reqCtx, cancel := context.WithTimeout(ctx, DefaultDownloadTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request for %s: %w", url, err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return retry.RetryableError(fmt.Errorf("HTTP request failed for %s: %w", url, err))
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
				return retry.RetryableError(fmt.Errorf("HTTP status %d for %s", resp.StatusCode, url))
			}
			return fmt.Errorf("HTTP status %d for %s", resp.StatusCode, url)
		}

		dir := filepath.Dir(destPath)
		tmpFile, err := os.CreateTemp(dir, "download-*")
		if err != nil {
			if os.IsNotExist(err) {
				if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil {
					return fmt.Errorf("failed to create directory %s: %w", dir, mkdirErr)
				}
				tmpFile, err = os.CreateTemp(dir, "download-*")
			}
			if err != nil {
				return fmt.Errorf("failed to create temp file in %s: %w", dir, err)
			}
		}
		tmpPath := tmpFile.Name()

		_, copyErr := io.Copy(tmpFile, resp.Body)
		closeErr := tmpFile.Close()

		if copyErr != nil {
			_ = os.Remove(tmpPath)
			return retry.RetryableError(fmt.Errorf("failed to write data: %w", copyErr))
		}
		if closeErr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to close temp file: %w", closeErr)
		}

		if err := os.Rename(tmpPath, destPath); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to move temp file to %s: %w", destPath, err)
		}

		return nil
	})
}
