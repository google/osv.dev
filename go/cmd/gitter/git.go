package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/internal/gitter"
	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/logger"
)

var (
	errCommitNotFound     = errors.New("commit not found in repository")
	errNotCommitObject    = errors.New("object is not a commit")
	errCommitPackTooLarge = errors.New("commit pack exceeds maximum allowed size")

	// Aligns with gitter.MaxCommitPackBytes (var so tests can override with t.Cleanup).
	maxCommitPackArchiveBytes int64 = gitter.MaxCommitPackBytes
)

// maxLogOutputBytes is the maximum length of command output included in debug logs (4 KB),
// preventing overwhelming log entries while preserving useful context.
const maxLogOutputBytes = 4096

type FetchOptions struct {
	ForceUpdate                 bool
	SkipReqConcurrencySemaphore bool
}

// truncateLogOutput truncates command output to maxLogOutputBytes for logging.
func truncateLogOutput(out []byte) string {
	if len(out) <= maxLogOutputBytes {
		return string(out)
	}

	return strings.ToValidUTF8(string(out[:maxLogOutputBytes]), "") + fmt.Sprintf("... [truncated %d bytes]", len(out)-maxLogOutputBytes)
}

// prepareCmd prepares the command with context cancellation handled by sending SIGINT.
// Git commands automatically set GIT_TERMINAL_PROMPT=0.
func prepareCmd(ctx context.Context, dir string, name string, args ...string) *exec.Cmd {
	//nolint: gosec // G702: The command arguments are mostly from within gitter
	// The only user controlled input is the repoURL, which is still from internal services
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if name == "git" {
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
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
// It logs cancellation errors separately as requested
func runCmd(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	cmd := prepareCmd(ctx, dir, name, args...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() != nil {
			// Log separately if cancelled
			logger.DebugContext(ctx, "Command cancelled", slog.String("cmd", name), slog.Any("err", ctx.Err()))
			return out, fmt.Errorf("command %s cancelled: %w", name, ctx.Err())
		}

		return out, fmt.Errorf("command %s failed: %w, output: %s", name, err, out)
	}

	logger.DebugContext(ctx, "Git command executed",
		slog.String("cmd", name),
		slog.Any("args", args),
		slog.String("output", truncateLogOutput(out)),
	)

	return out, nil
}

// cloneRepo clones a git repository into repoPath.
func cloneRepo(ctx context.Context, repoURL string, repoPath string) error {
	_, err := runCmd(ctx, "", "git", "clone", "--", repoURL, repoPath)
	return err
}

// Attempt to recover from git fetch errors
// Returns true if recovery was attempted and we should retry fetch
func attemptGitRecovery(ctx context.Context, repoPath string, err error) bool {
	if err == nil {
		return false
	}

	// Refname conflict, likely name conflict between local and remote refs
	// We can try removing stale remote-tracking branches and retry
	if isRefConflictError(err) {
		logger.WarnContext(ctx, "Ref conflict detected, running git remote prune origin")
		if _, err := runCmd(ctx, repoPath, "git", "remote", "prune", "origin"); err != nil {
			logger.WarnContext(ctx, "Failed to prune origin", slog.Any("err", err))
			return false
		}

		return true
	}

	// index.lock exists, likely a previous git operation got terminated and wasn't cleaned up properly.
	// We want to reclone as fallback but log a separate warning (for stats)
	if isIndexLockError(err) {
		logger.WarnContext(ctx, "index.lock exists, will reclone instead")
	}

	return false
}

// fetchRepo fetches remote origin and updates origin/HEAD to the remote's default branch.
// --tags is needed because a plain fetch only follows tags that point into fetched branch
// history, and some projects (e.g. php-src) tag each release on a commit no branch contains.
// --force lets a tag that was moved upstream be updated rather than failing the fetch.
// --prune and --prune-tags remove branches and tags that were deleted upstream.
func fetchRepo(ctx context.Context, repoPath string) error {
	_, err := runCmd(ctx, repoPath, "git", "-c", "remote.origin.followRemoteHead=always", "fetch", "--tags", "--prune", "--prune-tags", "--force", "origin")
	if err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	return nil
}

// refreshRepo updates the local repository on disk if it is stale or if forceUpdate is true.
// It clones the repository if it doesn't exist, or fetches it with error recovery and fallback recloning.
func refreshRepo(ctx context.Context, repoURL string, forceUpdate bool) error {
	logger.DebugContext(ctx, "Refreshing repository on disk")
	start := time.Now()

	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	repoLock := GetRepoLock(repoURL)
	if !forceUpdate {
		if lastFetchTime, ok := getLastFetch(repoURL); ok && time.Since(lastFetchTime) <= fetchTimeout {
			repoLock.RLock()
			_, statErr := os.Stat(filepath.Join(repoPath, ".git"))
			repoLock.RUnlock()
			if statErr == nil {
				logger.DebugContext(ctx, "Repository is fresh on disk, skipping exclusive lock")
				return nil
			}
		}
	}

	repoLock.Lock()
	defer repoLock.Unlock()

	lastFetchTime, ok := getLastFetch(repoURL)

	// Check if we need to fetch
	if forceUpdate || !ok || time.Since(lastFetchTime) > fetchTimeout {
		if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
			// Clone
			logger.DebugContext(ctx, "Cloning git repository")
			if err := cloneRepo(ctx, repoURL, repoPath); err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// Fetch and reset
			if ok {
				logger.DebugContext(ctx, "Fetching git repository", slog.Duration("sinceLastFetch", time.Since(lastFetchTime)))
			} else {
				logger.DebugContext(ctx, "Fetching git repository")
			}
			err := fetchRepo(ctx, repoPath)

			// Attempt recovery and fallback
			if err != nil {
				logger.WarnContext(ctx, "Initial fetch failed, attempting to recover", slog.Any("err", err))

				// Attempt recovery and retry fetch if successful
				if attemptGitRecovery(ctx, repoPath, err) {
					logger.DebugContext(ctx, "Retrying fetch after recovery")
					err = fetchRepo(ctx, repoPath)
				}

				// If still failing or recovery wasn't attempted, check if we should reclone as a fallback
				if err != nil {
					var reason string
					// isNotFoundError (404) is intentionally omitted here so that
					// if an upstream repository is deleted, the local clone is removed as well, and further attempts to reclone will 404.
					// This ensures we respect the upstream's decision to delete or private the repo, instead of serving stale content indefinitely.
					switch {
					case isAuthError(err):
						reason = "401 Unauthorized / auth error"
					case isForbiddenError(err):
						reason = "403 Forbidden"
					case isRateLimitError(err):
						reason = "upstream rate limit or load"
					case isRemoteHostError(err):
						reason = "remote host or network error"
					case osvutil.IsContextError(err):
						reason = "context cancelled"
					}

					if reason != "" {
						if ok {
							logger.WarnContext(ctx, "Fetch failed due to "+reason+". Using local repo.",
								slog.Duration("sinceLastFetch", time.Since(lastFetchTime)),
								slog.Any("err", err))
						} else {
							logger.WarnContext(ctx, "Fetch failed due to "+reason+". Using local repo.",
								slog.Any("err", err))
						}
						updateLastFetch(repoURL)

						return nil
					}

					logger.WarnContext(ctx, "Fetch failed after recovery attempt, deleting repo and recloning", slog.Any("err", err))
					if err := os.RemoveAll(repoPath); err != nil {
						return fmt.Errorf("failed to remove repo directory for reclone: %w", err)
					}

					logger.DebugContext(ctx, "Cloning git repository after fallback")
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

	logger.DebugContext(ctx, "Repository refresh completed", slog.Duration("duration", time.Since(start)))

	return nil
}

// SyncRepoOnDisk syncs/updates the repository on disk and returns a Repository struct with repoPath set.
// Skips the expensive LoadRepository (commit graph building and patch ID calculation).
func SyncRepoOnDisk(ctx context.Context, repoURL string, opts FetchOptions) (*Repository, error) {
	_, err, _ := gFetch.Do(repoURL, func() (any, error) {
		return runWithConcurrencyControl(ctx, opts.SkipReqConcurrencySemaphore, func() (any, error) {
			err := refreshRepo(ctx, repoURL, opts.ForceUpdate)
			return nil, err
		})
	})
	if err != nil {
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
		return runWithConcurrencyControl(ctx, opts.SkipReqConcurrencySemaphore, func() (any, error) {
			repoLock := GetRepoLock(repoURL)
			repoLock.RLock()
			defer repoLock.RUnlock()

			repo, err := LoadRepository(ctx, repoPath)
			if err != nil {
				logger.WarnContext(ctx, "Failed to load repository", slog.Any("error", err))
			}

			return repo, err
		})
	})
	if err != nil {
		return nil, err
	}
	repo := repoAny.(*Repository)
	repoCache.SetWithTTL(repoURL, repo, 0, repoTTL)

	return repo, nil
}

// ArchiveRepo compresses git repository into a blob
func ArchiveRepo(ctx context.Context, repoURL string) ([]byte, error) {
	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)
	archivePath := repoPath + ".zst"

	repoLock := GetRepoLock(repoURL)
	repoLock.Lock()
	defer repoLock.Unlock()

	lastFetchMu.Lock()
	lastFetchTime := lastFetch[repoURL]
	lastFetchMu.Unlock()

	// Check if archive needs update
	// We update if archive does not exist OR if it is older than the last fetch
	stats, err := os.Stat(archivePath)
	if os.IsNotExist(err) || (err == nil && stats.ModTime().Before(lastFetchTime)) {
		logger.DebugContext(ctx, "Archiving git blob")
		startArchive := time.Now()

		// Reset working tree to origin/HEAD before creating archive
		if _, err := runCmd(ctx, repoPath, "git", "reset", "--hard", "origin/HEAD"); err != nil {
			return nil, fmt.Errorf("git reset failed: %w", err)
		}

		// Archive
		// tar --zstd -cf <archivePath> -C "<gitStorePath>/<repoDirName>" .
		// using -C to archive the relative path so it unzips nicely
		_, err := runCmd(ctx, "", "tar", "--zstd", "-cf", archivePath, "-C", filepath.Join(gitStorePath, repoDirName), ".")
		if err != nil {
			return nil, fmt.Errorf("tar zstd failed: %w", err)
		}
		logger.DebugContext(ctx, "Archiving git blob completed", slog.Duration("duration", time.Since(startArchive)))
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

// resolveValidCommits runs a single batched `git cat-file --batch-check` against the
// cached repository to verify requested hashes are exact commit OIDs (rejecting missing
// objects, prefix abbreviations, and non-commit objects like tags, trees, or blobs).
func resolveValidCommits(ctx context.Context, absRepoPath string, commits []string, allowPartial bool) ([]string, error) {
	cmd := prepareCmd(ctx, absRepoPath, "git", "cat-file", "--batch-check=%(objectname) %(objecttype)")
	cmd.Stdin = strings.NewReader(strings.Join(commits, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, fmt.Errorf("git cat-file --batch-check failed: %w, output: %s", err, truncateLogOutput(stderr.Bytes()))
	}

	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != len(commits) {
		return nil, fmt.Errorf("unexpected git cat-file line count: got %d, want %d", len(lines), len(commits))
	}

	validCommits := make([]string, 0, len(commits))
	var hasMissing, hasNonCommit bool
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("unexpected git cat-file output for %s: %q", commits[i], line)
		}
		switch {
		case fields[1] == "commit" && fields[0] == commits[i]:
			validCommits = append(validCommits, commits[i])
		case fields[1] == "missing" || fields[1] == "commit":
			hasMissing = true
		default:
			hasNonCommit = true
		}
	}

	if !allowPartial && hasMissing {
		return nil, fmt.Errorf("%w: one or more requested commits missing", errCommitNotFound)
	}
	if len(validCommits) == 0 {
		if hasNonCommit && !hasMissing {
			return nil, fmt.Errorf("%w: requested objects are not commits", errNotCommitObject)
		}

		return nil, fmt.Errorf("%w: none of the requested commits exist", errCommitNotFound)
	}

	return validCommits, nil
}

// materializeDiffBlobs collects all blob OIDs touched by the requested commits (handling
// normal, root, and merge commits via `-m --first-parent --root`) in one batched diff-tree
// invocation and transfers them into shallowDir in a single delta-compressed pack stream.
func materializeDiffBlobs(ctx context.Context, absRepoPath, shallowDir string, validCommits []string) error {
	diffCmd := prepareCmd(ctx, absRepoPath, "git", "diff-tree", "--stdin", "-r", "--raw", "--no-renames", "--no-commit-id", "-m", "--first-parent", "--root")
	diffCmd.Stdin = strings.NewReader(strings.Join(validCommits, "\n") + "\n")
	var diffOut, diffErr bytes.Buffer
	diffCmd.Stdout = &diffOut
	diffCmd.Stderr = &diffErr
	if err := diffCmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("git diff-tree cancelled: %w", ctx.Err())
		}

		return fmt.Errorf("git diff-tree failed: %w, output: %s", err, truncateLogOutput(diffErr.Bytes()))
	}

	blobSet := make(map[string]struct{})
	addBlob := func(mode, oid string) {
		// Skip gitlink/submodule entries (160000) and all-zero absent OIDs.
		if mode == "160000" || strings.Trim(oid, "0") == "" {
			return
		}
		blobSet[oid] = struct{}{}
	}
	for line := range strings.SplitSeq(diffOut.String(), "\n") {
		meta, _, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasPrefix(meta, ":") {
			continue
		}
		parts := strings.Fields(meta[1:])
		if len(parts) < 4 {
			continue
		}
		addBlob(parts[0], parts[2])
		addBlob(parts[1], parts[3])
	}
	if len(blobSet) == 0 {
		return nil
	}

	var oidInput strings.Builder
	for oid := range blobSet {
		oidInput.WriteString(oid)
		oidInput.WriteByte('\n')
	}

	packCmd := prepareCmd(ctx, absRepoPath, "git", "pack-objects", "--stdout", "--quiet")
	packCmd.Stdin = strings.NewReader(oidInput.String())
	var packStderr bytes.Buffer
	packCmd.Stderr = &packStderr
	packPipe, err := packCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create pack-objects pipe: %w", err)
	}

	indexCmd := prepareCmd(ctx, "", "git", "--git-dir="+shallowDir, "index-pack", "--stdin", "--fix-thin")
	indexCmd.Stdin = packPipe
	indexCmd.Stdout = io.Discard
	var indexStderr bytes.Buffer
	indexCmd.Stderr = &indexStderr

	if err := packCmd.Start(); err != nil {
		return fmt.Errorf("git pack-objects start failed: %w", err)
	}
	if err := indexCmd.Start(); err != nil {
		_ = packPipe.Close()
		_ = packCmd.Wait()

		return fmt.Errorf("git index-pack start failed: %w", err)
	}

	// Wait for indexCmd before packCmd so all reads from packPipe complete first.
	indexErr := indexCmd.Wait()
	packErr := packCmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("blob transfer cancelled: %w", ctx.Err())
	}
	if packErr != nil {
		return fmt.Errorf("git pack-objects failed: %w, output: %s", packErr, truncateLogOutput(packStderr.Bytes()))
	}
	if indexErr != nil {
		return fmt.Errorf("git index-pack failed: %w, output: %s", indexErr, truncateLogOutput(indexStderr.Bytes()))
	}

	return nil
}

// CreateCommitPack creates a standalone shallow bare Git repository archive (.tar.zst)
// containing only the requested commit(s), their immediate parent(s), and the trees/blobs
// touched by each commit diff. It holds only a read lock on the cached repository during
// object extraction and releases it before config cleanup and compression.
func CreateCommitPack(ctx context.Context, repoURL string, commits []string, allowPartial bool) ([]byte, error) {
	absGitStore, err := filepath.Abs(gitStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve git store path: %w", err)
	}
	repoDirName := getRepoDirName(repoURL)
	absRepoPath := filepath.Clean(filepath.Join(absGitStore, repoDirName))
	if !strings.HasPrefix(absRepoPath, absGitStore+string(os.PathSeparator)) {
		return nil, fmt.Errorf("invalid repository path for %q", repoURL)
	}

	var tmpDir, shallowDir string
	defer func() {
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	gitShallow := func(args ...string) error {
		fullArgs := make([]string, 0, len(args)+1)
		fullArgs = append(fullArgs, "--git-dir="+shallowDir)
		fullArgs = append(fullArgs, args...)
		_, err := runCmd(ctx, "", "git", fullArgs...)

		return err
	}

	// Hold RLock only while reading from absRepoPath; release before config cleanup & archiving.
	if err := func() error {
		repoLock := GetRepoLock(repoURL)
		repoLock.RLock()
		defer repoLock.RUnlock()

		storeRoot, err := os.OpenRoot(absGitStore)
		if err != nil {
			return fmt.Errorf("failed to open git store root: %w", err)
		}
		defer storeRoot.Close()

		if _, err := storeRoot.Stat(filepath.Join(repoDirName, ".git")); err != nil {
			return fmt.Errorf("cached repository unavailable: %w", err)
		}

		// Verify requested commit hashes before allocating temp staging directories.
		validCommits, err := resolveValidCommits(ctx, absRepoPath, commits, allowPartial)
		if err != nil {
			return err
		}

		// Stage temp bare repos under gitter's work volume rather than limited node /tmp.
		if err := os.MkdirAll(commitPackTmpPath, 0755); err != nil {
			return fmt.Errorf("failed to create commit-pack temp root: %w", err)
		}
		tmpDir, err = os.MkdirTemp(commitPackTmpPath, "pack-*")
		if err != nil {
			return fmt.Errorf("failed to create temp dir for commit pack: %w", err)
		}
		shallowDir = filepath.Join(tmpDir, "repo.git")

		// 1. Init bare repo (preserving SHA-256 object format when requested).
		initArgs := []string{"init", "--bare", "--quiet"}
		if len(validCommits[0]) == 64 {
			initArgs = append(initArgs, "--object-format=sha256")
		}
		if err := gitShallow(initArgs...); err != nil {
			return fmt.Errorf("git init bare failed: %w", err)
		}

		// 2. Fetch ONLY the target commit(s) + immediate parents without blobs.
		// Configuring remote.origin.uploadpack avoids modifying the source repo's .git/config.
		fileRemoteURL := (&url.URL{Scheme: "file", Path: absRepoPath}).String()
		if err := gitShallow("remote", "add", "origin", fileRemoteURL); err != nil {
			return fmt.Errorf("git remote add failed: %w", err)
		}
		uploadPackCmd := "git -c uploadpack.allowFilter=true -c uploadpack.allowAnySHA1InWant=true upload-pack"
		if err := gitShallow("config", "remote.origin.uploadpack", uploadPackCmd); err != nil {
			return fmt.Errorf("git config uploadpack failed: %w", err)
		}

		fetchArgs := make([]string, 0, 6+len(validCommits))
		fetchArgs = append(fetchArgs, "fetch", "--quiet", "--filter=blob:none", "--depth=2", "--no-tags", "origin")
		fetchArgs = append(fetchArgs, validCommits...)
		if err := gitShallow(fetchArgs...); err != nil {
			return fmt.Errorf("git shallow fetch failed: %w", err)
		}

		// 3. Transfer ONLY the blobs touched by the requested commits in a single pack stream.
		return materializeDiffBlobs(ctx, absRepoPath, shallowDir, validCommits)
	}(); err != nil {
		return nil, err
	}

	// 4. Detach from gitter's promisor path & enable local filtered fetches for vanir.
	for _, cfgArgs := range [][]string{
		{"config", "--remove-section", "remote.origin"},
		{"config", "uploadpack.allowFilter", "true"},
		{"config", "uploadpack.allowAnySHA1InWant", "true"},
	} {
		if err := gitShallow(cfgArgs...); err != nil {
			return nil, fmt.Errorf("git %s failed: %w", strings.Join(cfgArgs, " "), err)
		}
	}
	// Drop sample hooks and FETCH_HEAD (which contains gitter's internal file:// store path).
	_ = os.RemoveAll(filepath.Join(shallowDir, "hooks"))
	_ = os.Remove(filepath.Join(shallowDir, "FETCH_HEAD"))

	// 5. Compress bare repo using tar --zstd (matching ArchiveRepo).
	archivePath := filepath.Join(tmpDir, "commit-pack.tar.zst")
	if _, err := runCmd(ctx, "", "tar", "--zstd", "-cf", archivePath, "-C", shallowDir, "."); err != nil {
		return nil, fmt.Errorf("tar zstd failed: %w", err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat commit pack archive: %w", err)
	}
	if info.Size() > maxCommitPackArchiveBytes {
		return nil, fmt.Errorf("%w (%d > %d bytes)", errCommitPackTooLarge, info.Size(), maxCommitPackArchiveBytes)
	}

	return os.ReadFile(archivePath)
}
