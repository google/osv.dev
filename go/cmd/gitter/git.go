package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/logger"
)

type FetchOptions struct {
	ForceUpdate   bool
	SkipSemaphore bool
}

// prepareCmd prepares the command with context cancellation handled by sending SIGINT.
func prepareCmd(ctx context.Context, dir string, env []string, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	// Use SIGINT instead of SIGKILL for graceful shutdown of subprocesses
	cmd.Cancel = func() error {
		logger.DebugContext(ctx, "SIGINT sent to command", slog.String("cmd", name), slog.Any("args", args))
		return cmd.Process.Signal(syscall.SIGINT)
	}
	// Ensure it eventually dies if it ignores SIGINT
	cmd.WaitDelay = shutdownTimeout / 2

	return cmd
}

// runCmd executes a command with context cancellation handled by sending SIGINT.
// It logs cancellation errors separately as requested.
func runCmd(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := prepareCmd(ctx, dir, env, name, args...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() != nil {
			// Log separately if cancelled
			logger.WarnContext(ctx, "Command cancelled", slog.String("cmd", name), slog.Any("err", ctx.Err()))
			return fmt.Errorf("command %s cancelled: %w", name, ctx.Err())
		}

		return fmt.Errorf("command %s failed: %w, output: %s", name, err, out)
	}

	logger.DebugContext(ctx, "Git command executed",
		slog.String("cmd", name),
		slog.Any("args", args),
		slog.String("output", string(out)),
	)

	return nil
}

// cloneRepo clones a git repository into repoPath.
func cloneRepo(ctx context.Context, repoURL string, repoPath string) error {
	return runCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "clone", "--", repoURL, repoPath)
}

func isIndexLockError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(errString, "index.lock") && strings.Contains(errString, "File exists")
}

func isRefConflictError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(errString, "refname conflict") ||
		(strings.Contains(errString, "some local refs could not be updated") && strings.Contains(errString, "try running 'git remote prune origin'"))
}

// Attempt to recover from git fetch + reset errors
// Returns true if recovery was attempted and we should retry fetch + reset
func attemptGitRecovery(ctx context.Context, repoPath string, err error) bool {
	if err == nil {
		return false
	}

	// Refname conflict, likely name conflict between local and remote refs
	// We can try removing stale remote-tracking branches and retry
	if isRefConflictError(err) {
		logger.WarnContext(ctx, "Ref conflict detected, running git remote prune origin")
		if err := runCmd(ctx, repoPath, nil, "git", "remote", "prune", "origin"); err != nil {
			logger.ErrorContext(ctx, "Failed to prune origin", slog.Any("err", err))
			return false
		}

		return true
	}

	// index.lock exists, likely a previous git reset got terminated and wasn't cleaned up properly.
	// We want to reclone as fallback but log a separate warning (for stats)
	if isIndexLockError(err) {
		logger.WarnContext(ctx, "index.lock exists, will reclone instead")
	}

	return false
}

// fetchAndResetRepo fetches remote origin and resets working directory to origin/HEAD.
func fetchAndResetRepo(ctx context.Context, repoPath string) error {
	err := runCmd(ctx, repoPath, nil, "git", "fetch", "origin")
	if err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	// Make sure origin/HEAD points to the latest default branch from remotes
	err = runCmd(ctx, repoPath, nil, "git", "remote", "set-head", "origin", "--auto")
	if err != nil {
		logger.WarnContext(ctx, "git remote set-head failed: ", slog.Any("err", err))
	}

	err = runCmd(ctx, repoPath, nil, "git", "reset", "--hard", "origin/HEAD")
	if err != nil {
		return fmt.Errorf("git reset failed: %w", err)
	}

	return nil
}

func FetchRepo(ctx context.Context, repoURL string, forceUpdate bool) error {
	logger.DebugContext(ctx, "Starting fetch repo")
	start := time.Now()

	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	repoLock := GetRepoLock(repoURL)
	repoLock.Lock()
	defer repoLock.Unlock()

	lastFetchMu.Lock()
	accessTime, ok := lastFetch[repoURL]
	lastFetchMu.Unlock()

	// Check if we need to fetch
	if forceUpdate || !ok || time.Since(accessTime) > fetchTimeout {
		if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
			// Clone
			logger.DebugContext(ctx, "Cloning git repository", slog.Duration("sinceAccessTime", time.Since(accessTime)))
			if err := cloneRepo(ctx, repoURL, repoPath); err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// Fetch and reset
			logger.DebugContext(ctx, "Fetching git repository", slog.Duration("sinceAccessTime", time.Since(accessTime)))
			err := fetchAndResetRepo(ctx, repoPath)

			// Attempt recovery and fallback
			if err != nil {
				logger.WarnContext(ctx, "Initial fetch and reset failed, attempting to recover", slog.Any("err", err))

				// Attempt recovery and retry fetch and reset if successful
				if attemptGitRecovery(ctx, repoPath, err) {
					logger.InfoContext(ctx, "Retrying fetch and reset after recovery")
					err = fetchAndResetRepo(ctx, repoPath)
				}

				// If still failing or recovery wasn't attempted, reclone the repo as final fallback
				if err != nil {
					if isForbiddenError(err) {
						logger.WarnContext(ctx, "Fetch failed with 403 Forbidden. Using local repo.", slog.Duration("sinceLastFetch", time.Since(accessTime)), slog.Any("err", err))
						return nil
					}

					logger.WarnContext(ctx, "Fetch and reset failed after recovery attempt, deleting repo and recloning", slog.Any("err", err))
					if err := os.RemoveAll(repoPath); err != nil {
						return fmt.Errorf("failed to remove repo directory for reclone: %w", err)
					}

					logger.InfoContext(ctx, "Cloning git repository after fallback", slog.Duration("sinceAccessTime", time.Since(accessTime)))
					if err := cloneRepo(ctx, repoURL, repoPath); err != nil {
						return fmt.Errorf("git clone failed after fallback: %w", err)
					}
				}
			}
		}

		updateLastFetch(repoURL)
	}

	// Double check if the git directory exist
	_, err := os.Stat(filepath.Join(repoPath, ".git"))
	if err != nil {
		if os.IsNotExist(err) {
			deleteLastFetch(repoURL)
		}

		return fmt.Errorf("failed to read file: %w", err)
	}

	logger.InfoContext(ctx, "Fetch completed", slog.Duration("duration", time.Since(start)))

	return nil
}

// SyncRepoOnDisk syncs/updates the repository on disk and returns a Repository struct with repoPath set
// Skips the expensive LoadRepository (commit graph building and patch ID calculation)
func SyncRepoOnDisk(ctx context.Context, repoURL string, opts FetchOptions) (*Repository, error) {
	_, err, _ := gFetch.Do(repoURL, func() (any, error) {
		return runWithSemaphore(ctx, opts.SkipSemaphore, func() (any, error) {
			return nil, FetchRepo(ctx, repoURL, opts.ForceUpdate)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error syncing repository on disk", slog.Any("error", err))
		return nil, err
	}

	return NewRepository(repoURL), nil
}

// LoadRepo handles fetching and loading of a repository into RAM (commit graph, patch IDs).
// If opts.ForceUpdate is false, it will use the in-memory cache if available.
func LoadRepo(ctx context.Context, repoURL string, opts FetchOptions) (*Repository, error) {
	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	if !opts.ForceUpdate {
		if repo, ok := repoCache.Get(repoURL); ok {
			// repoCache.Get() will not return expired items, so we can safely return the repo
			logger.DebugContext(ctx, "Repository already in cache, skipping fetch and load")
			return repo, nil
		}
	}

	if _, err := SyncRepoOnDisk(ctx, repoURL, opts); err != nil {
		return nil, err
	}

	repoAny, err, _ := gLoad.Do(repoURL, func() (any, error) {
		return runWithSemaphore(ctx, opts.SkipSemaphore, func() (any, error) {
			repoLock := GetRepoLock(repoURL)
			repoLock.RLock()
			defer repoLock.RUnlock()

			return LoadRepository(ctx, repoPath)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load repository", slog.Any("error", err))
		return nil, err
	}
	repo := repoAny.(*Repository)
	repoCache.SetWithTTL(repoURL, repo, 0, repoTTL)

	return repo, nil
}

func ArchiveRepo(ctx context.Context, repoURL string) ([]byte, error) {
	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)
	archivePath := repoPath + ".zst"

	repoLock := GetRepoLock(repoURL)
	repoLock.RLock()
	defer repoLock.RUnlock()

	lastFetchMu.Lock()
	accessTime := lastFetch[repoURL]
	lastFetchMu.Unlock()

	// Check if archive needs update
	// We update if archive does not exist OR if it is older than the last fetch
	stats, err := os.Stat(archivePath)
	if os.IsNotExist(err) || (err == nil && stats.ModTime().Before(accessTime)) {
		logger.DebugContext(ctx, "Archiving git blob")
		startArchive := time.Now()
		// Archive
		// tar --zstd -cf <archivePath> -C "<gitStorePath>/<repoDirName>" .
		// using -C to archive the relative path so it unzips nicely
		err := runCmd(ctx, "", nil, "tar", "--zstd", "-cf", archivePath, "-C", filepath.Join(gitStorePath, repoDirName), ".")
		if err != nil {
			return nil, fmt.Errorf("tar zstd failed: %w", err)
		}
		logger.InfoContext(ctx, "Archiving git blob completed", slog.Duration("duration", time.Since(startArchive)))
	}

	// If the context is cancelled, still do the fetching stuff, just don't bother returning the result
	// As we can still cache the result and reply faster next time.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	fileData, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return fileData, nil
}
