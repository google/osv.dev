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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// SubprocessReadCloser wraps a command's stdout pipe and ensures the subprocess
// is waited for and input resources are closed when Close() is called.
type SubprocessReadCloser struct {
	io.ReadCloser
	cmd         *exec.Cmd
	bodyToClose io.Closer
}

// Close closes the underlying reader pipe, any input reader, and waits for the subprocess.
func (s *SubprocessReadCloser) Close() error {
	var errs []error
	if s.ReadCloser != nil {
		if err := s.ReadCloser.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.bodyToClose != nil {
		if err := s.bodyToClose.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.cmd != nil {
		if err := s.cmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && !exitErr.Success() {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func getXZDecompressCommand() (string, error) {
	if _, err := exec.LookPath("xz"); err == nil {
		return "xz", nil
	}
	if _, err := exec.LookPath("unxz"); err == nil {
		return "unxz", nil
	}
	return "", errors.New("neither 'xz' nor 'unxz' command-line tool found in PATH")
}

// DecompressXZ streams an xz-compressed reader through the system xz or unxz command.
func DecompressXZ(ctx context.Context, r io.Reader) (io.ReadCloser, error) {
	decompressCmd, err := getXZDecompressCommand()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, decompressCmd, "-dc")
	cmd.Stdin = r
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe for %s: %w", decompressCmd, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", decompressCmd, err)
	}

	var bodyToClose io.Closer
	if closer, ok := r.(io.Closer); ok {
		bodyToClose = closer
	}

	return &SubprocessReadCloser{
		ReadCloser:  stdout,
		cmd:         cmd,
		bodyToClose: bodyToClose,
	}, nil
}

// DecompressXZFile decompresses a local xz-compressed file.
func DecompressXZFile(ctx context.Context, xzFilePath string) (io.ReadCloser, error) {
	f, err := os.Open(xzFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", xzFilePath, err)
	}

	return DecompressXZ(ctx, f)
}

// FetchAndDecompressXZ fetches an xz-compressed URL over HTTP and streams
// its decompressed content directly through xz/unxz without saving to disk.
func FetchAndDecompressXZ(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP status %d fetching %s", resp.StatusCode, url)
	}

	return DecompressXZ(ctx, resp.Body)
}
