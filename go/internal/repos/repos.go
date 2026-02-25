// Package repos provides utilities for managing and cloning source repositories.
package repos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v6"
	"github.com/google/osv.dev/go/logger"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var ErrRepoInaccessible = errors.New("repo inaccessible")

// More performant mirrors for large/popular repos.
var gitMirrors = map[string]string{
	"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git": "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux.git",
}

func gitMirror(gitURL string) string {
	if mirror, ok := gitMirrors[strings.TrimRight(gitURL, "/")]; ok {
		logger.Info("Using mirror for git URL", slog.String("mirror", mirror), slog.String("git_url", gitURL))
		return mirror
	}

	return gitURL
}

func CloneToDir(ctx context.Context, repoURL string, dir string, forceUpdate bool) (*git.Repository, error) {
	// If the dir exists, check if it's a git repo. If so, pull the latest changes.
	// If not, clone the repo into the dir.
	_, err := os.Stat(dir)
	if err == nil {
		// Dir exists, check if it's a git repo.
		repo, err := git.PlainOpen(dir)
		if err == nil {
			// It's a git repo, pull the latest changes.
			if forceUpdate {
				cmd := exec.CommandContext(ctx, "git", "pull")
				cmd.Dir = dir
				cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
				output, err := cmd.CombinedOutput()
				if err != nil {
					return nil, fmt.Errorf("failed to pull repo: %w\n%s", err, string(output))
				}
				logger.Info("Pulled latest changes", slog.String("repo_url", repoURL), slog.String("dir", dir), slog.String("output", string(output)))

				// re-open the repo to get the new HEAD
				return git.PlainOpen(dir)
			}

			return repo, nil
		}
		logger.Warn("Could not open existing directory as git repo. Deleting it and cloning from scratch", slog.String("dir", dir), slog.Any("error", err))
		if err := os.RemoveAll(dir); err != nil {
			return nil, fmt.Errorf("failed to remove directory: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	repoURL = gitMirror(repoURL)
	if gitterHost := os.Getenv("GITTER_HOST"); gitterHost != "" {
		repo, err := cloneToDirGitter(ctx, gitterHost, repoURL, dir, forceUpdate)
		if err == nil {
			return repo, nil
		}
		if errors.Is(err, ErrRepoInaccessible) {
			return nil, err
		}
		logger.Error("Failed to get repo from gitter", slog.String("url", repoURL), slog.Any("error", err))
		logger.Info("Falling back to regular clone")
	}

	// regular clone
	cmd := exec.CommandContext(ctx, "git", "clone", "--", repoURL, dir)
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to clone repo: %w\n%s", err, string(output))
	}

	return git.PlainOpen(dir)
}

func cloneToDirGitter(ctx context.Context, gitterHost, repoURL, dir string, forceUpdate bool) (*git.Repository, error) {
	w, err := gitterGet(ctx, gitterHost, repoURL, forceUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo from gitter: %w", err)
	}
	// write tar.zst into file
	defer w.Close()
	tmpDir, err := os.MkdirTemp("", "gitter-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	tarPath := filepath.Join(tmpDir, "repo.tar.zst")
	f, err := os.Create(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tar file: %w", err)
	}
	defer f.Close()
	_, err = io.Copy(f, w)
	if err != nil {
		return nil, fmt.Errorf("failed to write tar file: %w", err)
	}
	// shell out to tar xf
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarPath, "-C", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to untar repo: %w\n%s", err, string(output))
	}
	// clean up
	if err := os.RemoveAll(tmpDir); err != nil {
		logger.Error("Failed to remove temp dir", slog.String("dir", tmpDir), slog.Any("error", err))
	}

	return git.PlainOpen(dir)
}

func gitterGet(ctx context.Context, gitterHost, repoURL string, forceUpdate bool) (io.ReadCloser, error) {
	getGitURL, err := url.JoinPath(gitterHost, "git")
	if err != nil {
		return nil, fmt.Errorf("failed to join path: %w", err)
	}
	// Use a custom transport to add OpenTelemetry tracing.
	client := http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getGitURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	vals := req.URL.Query()
	vals.Set("url", repoURL)
	if forceUpdate {
		vals.Set("force-update", "true")
	}
	req.URL.RawQuery = vals.Encode()
	logger.Info("Getting repo from gitter", slog.String("url", req.URL.String()))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo from gitter: %w", err)
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrRepoInaccessible
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to clone repo: %s", resp.Status)
	}

	return resp.Body, nil
}
