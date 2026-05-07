// Package main is the main package for gitter caching service
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "net/http/pprof" //nolint:gosec // This is a internal only service not public to the internet

	"github.com/dgraph-io/ristretto/v2"
	"github.com/dustin/go-humanize"
	"github.com/google/osv.dev/go/logger"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
)

type contextKey string

const (
	urlKey contextKey = "repoURL"
)

const defaultGitterWorkDir = "/work/gitter"
const persistenceFileName = "last-fetch.json"
const gitStoreFileName = "git-store"

// API Endpoints
var endpointHandlers = map[string]http.HandlerFunc{
	"GET /git":               gitHandler,
	"POST /cache":            cacheHandler,
	"GET /tags":              tagsHandler,
	"POST /affected-commits": affectedCommitsHandler,
}

var (
	gFetch          singleflight.Group
	gArchive        singleflight.Group
	gLoad           singleflight.Group
	gLsRemote       singleflight.Group
	gLocalTags      singleflight.Group
	persistencePath = filepath.Join(defaultGitterWorkDir, persistenceFileName)
	gitStorePath    = filepath.Join(defaultGitterWorkDir, gitStoreFileName)
	fetchTimeout    time.Duration
	semaphore       chan struct{} // Request concurrency control
	// LRU cache for recently loaded repositories (key: repo URL)
	repoCache             *ristretto.Cache[string, *Repository]
	repoTTL               time.Duration
	repoCacheMaxCostBytes int64
	// Cache for invalid (does not exist, or does not have tags) repos
	// Maps repo URL to the HTTP status code (404 or 204) to return
	invalidRepoCache           *ristretto.Cache[string, int]
	invalidRepoTTL             time.Duration
	invalidRepoCacheMaxEntries int64
)

const shutdownTimeout = 10 * time.Second

type SeparatedEvents struct {
	Introduced   []string
	Fixed        []string
	LastAffected []string
	Limit        []string
}

func separateEvents(events []*pb.Event) (*SeparatedEvents, error) {
	se := &SeparatedEvents{}
	for _, event := range events {
		switch event.GetEventType() {
		case pb.EventType_INTRODUCED:
			se.Introduced = append(se.Introduced, event.GetHash())
		case pb.EventType_FIXED:
			se.Fixed = append(se.Fixed, event.GetHash())
		case pb.EventType_LAST_AFFECTED:
			se.LastAffected = append(se.LastAffected, event.GetHash())
		case pb.EventType_LIMIT:
			se.Limit = append(se.Limit, event.GetHash())
		default:
			return nil, fmt.Errorf("invalid event type: %s", event.GetEventType())
		}
	}

	if len(se.Limit) > 0 && (len(se.Fixed) > 0 || len(se.LastAffected) > 0) {
		return nil, errors.New("limit and fixed/last_affected shouldn't exist in the same request")
	}

	return se, nil
}

// repoLocks is a map of per-repository RWMutexes, with url as the key.
// It coordinates access between write operations (FetchRepo) that modify the git directory on disk
// and read operations (ArchiveRepo, LoadRepository, etc).
// It mainly handles:
// - Ensuring reads and writes are mutually exclusive.
// - Allowing multiple concurrent reads.
var repoLocks sync.Map

func GetRepoLock(repoURL string) *sync.RWMutex {
	lock, _ := repoLocks.LoadOrStore(repoURL, &sync.RWMutex{})
	return lock.(*sync.RWMutex)
}

// repoCostBytes is the cost function for a repository in the LRU cache.
// The memory cost of a repository is approximated from the num of commits and a base overhead.
func repoCostBytes(repo *Repository) int64 {
	// Mutex (8 bytes), string for repo path (say 128 bytes), root commit (assume 1 root only, 32 bytes)
	repoOverhead := 168
	// Assuming per commit adds:
	// - Commit struct (Hash, PatchID, Parent []int of size 1, Tags []string)
	//   = 20 + 20 + 24 + 8 + 24 + <string len> ~= 128 bytes
	// - 1 pointer into []*Commit
	//   = 8 bytes
	// - 1 entry in commitGraph ([][]int, assuming linear history)
	//   = 24 + 8 = 32 bytes
	// - 1 entry to hashToIndex (map[SHA1]int)
	//   = 20 + 8 ~= 32 bytes
	// - 1 entry to patchIDToCommits (map[SHA1][]int, assuming all commits are unique)
	//   = 20 + 24 + 8 ~= 64 bytes
	// TOTAL: 264 bytes -> We round up to 300 for some buffer
	costPerCommit := 300

	return int64(repoOverhead + len(repo.commits)*costPerCommit)
}

// General guidance is to make NumCounters 10x the cache capacity (in terms of items)
// We're assuming the cache will hold 5000 repositories
const numCounters = int64(10 * 5000)

// InitRepoCache initializes the LRU cache for repositories.
func InitRepoCache() {
	var err error
	repoCache, err = ristretto.NewCache(&ristretto.Config[string, *Repository]{
		NumCounters: numCounters,
		MaxCost:     repoCacheMaxCostBytes,
		BufferItems: 64,
		Cost:        repoCostBytes,
		// Check for TTL expiry every 60 seconds
		TtlTickerDurationInSec: 60,
	})
	if err != nil {
		logger.FatalContext(context.Background(), "Failed to initialize repository cache", slog.Any("err", err))
	}
}

// CloseRepoCache closes the LRU cache.
func CloseRepoCache() {
	if repoCache != nil {
		repoCache.Close()
	}
}

// InitInvalidRepoCache initializes the cache for invalid repositories.
func InitInvalidRepoCache() {
	var err error
	invalidRepoCache, err = ristretto.NewCache(&ristretto.Config[string, int]{
		NumCounters: invalidRepoCacheMaxEntries * 10,
		MaxCost:     invalidRepoCacheMaxEntries, // Cost for each entry is 1
		BufferItems: 64,
		// Check for TTL expiry every 60 seconds
		TtlTickerDurationInSec: 60,
	})
	if err != nil {
		logger.FatalContext(context.Background(), "Failed to initialize invalid repository cache", slog.Any("err", err))
	}
}

// CloseInvalidRepoCache closes the cache for invalid repositories.
func CloseInvalidRepoCache() {
	if invalidRepoCache != nil {
		invalidRepoCache.Close()
	}
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
	logger.DebugContext(ctx, "Running command", slog.String("cmd", name), slog.Any("args", args))
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
	logger.DebugContext(ctx, "Command completed successfully", slog.String("cmd", name), slog.String("out", string(out)))

	return nil
}

// runWithSemaphore runs function after waiting at semaphore for concurrency control
func runWithSemaphore(ctx context.Context, f func() (any, error)) (any, error) {
	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
		logger.DebugContext(ctx, "Concurrent requests", slog.Int("count", len(semaphore)))

		return f()
	case <-ctx.Done():
		logger.WarnContext(ctx, "Request cancelled while waiting for semaphore")
		return nil, ctx.Err()
	}
}

func isLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, it might be a raw IP (though rare in RemoteAddr),
		// or an empty string. Try parsing the whole string as an IP.
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check if it's a loopback address (covers 127.0.0.0/8 and ::1)
	return ip.IsLoopback()
}

func prepareURL(r *http.Request, repoURL string) (string, error) {
	if repoURL == "" {
		return "", errors.New("missing url parameter")
	}

	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("error parsing url: %w", err)
	}

	// Convert git://github.com to https://github.com because it times out for some reason
	// git protocol on non-github urls works fine
	if u.Scheme == "git" && u.Host == "github.com" {
		u.Scheme = "https"
	}

	// Remove query and fragment from the URL
	u.RawQuery = ""
	u.Fragment = ""

	if !isLocalRequest(r) {
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "git" {
			return "", fmt.Errorf("unsupported protocol: %s", u.Scheme)
		}
	}

	logger.Info("Prepared URL", slog.String("from", repoURL), slog.String("to", u.String()))

	return u.String(), nil
}

func getRepoDirName(repoURL string) string {
	base := path.Base(repoURL)
	base = filepath.Base(base)
	base = strings.TrimSuffix(base, ".git")
	hash := sha256.Sum256([]byte(repoURL))

	return fmt.Sprintf("%s-%s", base, hex.EncodeToString(hash[:]))
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(errString, "could not read Username") ||
		strings.Contains(errString, "Authentication failed") ||
		strings.Contains(errString, "The requested URL returned error: 403")
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(strings.ToLower(errString), "repository") && strings.Contains(strings.ToLower(errString), "not found")
}

// Helper function to unmarshal request body based on Content-Type (protobuf or JSON)
func unmarshalRequest(r *http.Request, body proto.Message) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		return protojson.Unmarshal(data, body)
	}
	// Default to protobuf
	return proto.Unmarshal(data, body)
}

// Helper function to marshal response body based on Content-Type (protobuf or JSON)
func marshalResponse(r *http.Request, m proto.Message) ([]byte, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		return protojson.Marshal(m)
	}
	// Default to protobuf
	return proto.Marshal(m)
}

func doFetch(ctx context.Context, w http.ResponseWriter, repoURL string, forceUpdate bool) error {
	_, err, _ := gFetch.Do(repoURL, func() (any, error) {
		return runWithSemaphore(ctx, func() (any, error) {
			return nil, FetchRepo(ctx, repoURL, forceUpdate)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error fetching blob", slog.Any("error", err))
		if isAuthError(err) {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusForbidden)
		} else if isNotFoundError(err) {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusInternalServerError)
		}

		return err
	}

	return nil
}

// getFreshRepo handles fetching and loading of a repository
// If forceUpdate is true, it will always refetch and rebuild the repository (commit graph, patch ID, etc)
// Otherwise, it will use a cache if available
func getFreshRepo(ctx context.Context, w http.ResponseWriter, repoURL string, forceUpdate bool) (*Repository, error) {
	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	if !forceUpdate {
		if repo, ok := repoCache.Get(repoURL); ok {
			// repoCache.Get() will not return expired items, so we can safely return the repo
			logger.DebugContext(ctx, "Repository already in cache, skipping fetch and load")
			return repo, nil
		}
	}

	if err := doFetch(ctx, w, repoURL, forceUpdate); err != nil {
		return nil, err
	}

	repoAny, err, _ := gLoad.Do(repoURL, func() (any, error) {
		return runWithSemaphore(ctx, func() (any, error) {
			repoLock := GetRepoLock(repoURL)
			repoLock.RLock()
			defer repoLock.RUnlock()

			return LoadRepository(ctx, repoPath)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load repository", slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to load repository: %v", err), http.StatusInternalServerError)

		return nil, err
	}
	repo := repoAny.(*Repository)
	repoCache.SetWithTTL(repoURL, repo, 0, repoTTL)

	return repo, nil
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
		logger.WarnContext(ctx, "ref conflict detected, running git remote prune origin")
		if err := runCmd(ctx, repoPath, nil, "git", "remote", "prune", "origin"); err != nil {
			logger.ErrorContext(ctx, "failed to prune origin", slog.Any("err", err))
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

// Helper function to group git fetch and git reset --hard together
func fetchAndReset(ctx context.Context, repoPath string) error {
	err := runCmd(ctx, repoPath, nil, "git", "fetch", "origin")
	if err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	err = runCmd(ctx, repoPath, nil, "git", "reset", "--hard", "origin/HEAD")
	if err != nil {
		return fmt.Errorf("git reset failed: %w", err)
	}

	return nil
}

func FetchRepo(ctx context.Context, repoURL string, forceUpdate bool) error {
	logger.InfoContext(ctx, "Starting fetch repo")
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
			logger.InfoContext(ctx, "Cloning git repository", slog.Duration("sinceAccessTime", time.Since(accessTime)))
			err := runCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "clone", "--", repoURL, repoPath)
			if err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// Fetch and reset
			logger.InfoContext(ctx, "Fetching git repository", slog.Duration("sinceAccessTime", time.Since(accessTime)))
			err := fetchAndReset(ctx, repoPath)

			// Attempt recovery and fallback
			if err != nil {
				logger.WarnContext(ctx, "Initial fetch and reset failed, attempting to recover", slog.Any("err", err))

				// Attempt recovery and retry fetch and reset if successful
				if attemptGitRecovery(ctx, repoPath, err) {
					logger.InfoContext(ctx, "Retrying fetch and reset after recovery")
					err = fetchAndReset(ctx, repoPath)
				}

				// If still failing or recovery wasn't attempted, reclone the repo as final fallback
				if err != nil {
					logger.WarnContext(ctx, "Fetch and reset failed after recovery attempt, deleting repo and recloning", slog.Any("err", err))
					if err := os.RemoveAll(repoPath); err != nil {
						return fmt.Errorf("failed to remove repo directory for reclone: %w", err)
					}

					logger.InfoContext(ctx, "Cloning git repository after fallback", slog.Duration("sinceAccessTime", time.Since(accessTime)))
					err := runCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "clone", "--", repoURL, repoPath)
					if err != nil {
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
		logger.InfoContext(ctx, "Archiving git blob")
		// Archive
		// tar --zstd -cf <archivePath> -C "<gitStorePath>/<repoDirName>" .
		// using -C to archive the relative path so it unzips nicely
		err := runCmd(ctx, "", nil, "tar", "--zstd", "-cf", archivePath, "-C", filepath.Join(gitStorePath, repoDirName), ".")
		if err != nil {
			return nil, fmt.Errorf("tar zstd failed: %w", err)
		}
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

func main() {
	logger.InitGlobalLogger()
	logger.RegisterContextKey(urlKey, "repoURL")
	defer logger.Close()

	port := flag.Int("port", 8888, "Listen port")
	workDir := flag.String("work-dir", defaultGitterWorkDir, "Work directory")
	flag.DurationVar(&fetchTimeout, "fetch-timeout", time.Hour, "Fetch timeout duration")
	concurrentLimit := flag.Int("concurrent-limit", 100, "Concurrent limit for unique requests")
	flag.DurationVar(&repoTTL, "repo-cache-ttl", time.Hour, "Repository LRU cache time-to-live duration")
	repoMaxCostStr := flag.String("repo-cache-max-cost", "1GiB", "Repository LRU cache max cost (in bytes)")
	flag.DurationVar(&invalidRepoTTL, "invalid-repo-cache-ttl", time.Hour, "Invalid repository cache time-to-live duration")
	flag.Int64Var(&invalidRepoCacheMaxEntries, "invalid-repo-cache-max-entries", 5000, "Invalid repository cache max entries")
	flag.Parse()
	semaphore = make(chan struct{}, *concurrentLimit)

	persistencePath = filepath.Join(*workDir, persistenceFileName)
	gitStorePath = filepath.Join(*workDir, gitStoreFileName)
	if err := os.MkdirAll(gitStorePath, 0755); err != nil {
		logger.Fatal("Failed to create git store path", slog.String("path", gitStorePath), slog.Any("error", err))
	}

	repoMaxCostUint, err := humanize.ParseBytes(*repoMaxCostStr)
	if err != nil {
		logger.Fatal("Failed to parse repo cache max cost", slog.String("maxCost", *repoMaxCostStr), slog.Any("error", err))
	}
	if repoMaxCostUint > math.MaxInt64 {
		logger.Fatal("Repo cache max cost too large", slog.Uint64("maxCost", repoMaxCostUint))
	}
	repoCacheMaxCostBytes = int64(repoMaxCostUint)

	loadLastFetchMap()
	InitRepoCache()
	defer CloseRepoCache()
	InitInvalidRepoCache()
	defer CloseInvalidRepoCache()

	// Create a context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for endpoint, handler := range endpointHandlers {
		http.Handle(endpoint, otelhttp.NewHandler(handler, endpoint))
	}

	logger.Info("Gitter starting and listening", slog.Int("port", *port))

	// --- Server Shutdown Protocol ---
	// This is what happens when a kubernetes send a SIGTERM signal:
	// 1. Kubernetes sends SIGTERM to the process
	// 2. The process receives the signal and prints "Shutting down gracefully..."
	// 3. The process calls server.Shutdown(ctx) to close incoming connections, and wait for timeout.
	// 4. The context within each request will be automatically cancelled (does not wait for timeout).
	// 5. Any subprocesses will be sent SIGINT, with a timeout / 2 duration before SIGKILL.
	// 6. The server waits for the timeout to finish processing all requests.
	// 7. We save the lastFetch map to disk.
	// 8. The process exits

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		ReadHeaderTimeout: 3 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			// Return the context tied to the termination signal.
			return ctx
		},
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Gitter failed to start", slog.Int("port", *port), slog.Any("error", err))
		}
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	logger.Info("Shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", slog.Any("error", err))
	}

	saveLastFetchMap()
	logger.Info("Server exiting")
}

func gitHandler(w http.ResponseWriter, r *http.Request) {
	repoURL, err := prepareURL(r, r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	forceUpdate := r.URL.Query().Get("force-update") == "true"

	ctx := context.WithValue(r.Context(), urlKey, repoURL)
	logger.InfoContext(ctx, "Received request: /git", slog.Bool("forceUpdate", forceUpdate), slog.String("remoteAddr", r.RemoteAddr))

	// Fetch repo first
	if err := doFetch(ctx, w, repoURL, forceUpdate); err != nil {
		return
	}

	// Archive repo
	fileDataAny, err, _ := gArchive.Do(repoURL, func() (any, error) {
		return runWithSemaphore(ctx, func() (any, error) {
			return ArchiveRepo(ctx, repoURL)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error archiving blob", slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Error archiving blob: %v", err), http.StatusInternalServerError)

		return
	}
	fileData := fileDataAny.([]byte)

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", "attachment; filename=\"git-blob.zst\"")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, bytes.NewReader(fileData)); err != nil {
		logger.ErrorContext(ctx, "Error copying file", slog.Any("error", err))
		http.Error(w, "Error copying file", http.StatusInternalServerError)

		return
	}

	logger.InfoContext(ctx, "Request completed successfully: /git")
}

func cacheHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body := &pb.CacheRequest{}
	if err := unmarshalRequest(r, body); err != nil {
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), http.StatusBadRequest)
		return
	}

	repoURL, err := prepareURL(r, body.GetUrl())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), urlKey, repoURL)
	logger.InfoContext(ctx, "Received request: /cache")

	if _, err := getFreshRepo(ctx, w, repoURL, body.GetForceUpdate()); err != nil {
		return
	}

	w.WriteHeader(http.StatusOK)
	logger.InfoContext(ctx, "Request completed successfully: /cache", slog.Duration("duration", time.Since(start)))
}

func affectedCommitsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body := &pb.AffectedCommitsRequest{}
	if err := unmarshalRequest(r, body); err != nil {
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), http.StatusBadRequest)
		return
	}

	repoURL, err := prepareURL(r, body.GetUrl())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	se, err := separateEvents(body.GetEvents())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cherrypickIntro := body.GetDetectCherrypicksIntroduced()
	cherrypickFixed := body.GetDetectCherrypicksFixed()
	cherrypickLimit := body.GetDetectCherrypicksLimit()
	considerAllBranches := body.GetConsiderAllBranches()

	// If cherrypick is true, consider all branches must be true
	if cherrypickIntro || cherrypickFixed {
		considerAllBranches = true
	}

	ctx := context.WithValue(r.Context(), urlKey, repoURL)
	logger.InfoContext(ctx, "Received request: /affected-commits",
		slog.Any("introduced", se.Introduced),
		slog.Any("fixed", se.Fixed),
		slog.Any("last_affected", se.LastAffected),
		slog.Any("limit", se.Limit),
		slog.Bool("cherrypickIntro", cherrypickIntro),
		slog.Bool("cherrypickFixed", cherrypickFixed),
		slog.Bool("cherrypickLimit", cherrypickLimit),
		slog.Bool("considerAllBranches", considerAllBranches),
	)

	repo, err := getFreshRepo(ctx, w, repoURL, body.GetForceUpdate())
	if err != nil {
		return
	}

	var affectedCommits []*Commit
	var cherrypicks cherrypickedHashes

	switch {
	case len(se.Limit) > 0:
		affectedCommits, cherrypicks = repo.Limit(ctx, se, cherrypickIntro, cherrypickLimit)
	case considerAllBranches:
		affectedCommits, cherrypicks = repo.Affected(ctx, se, cherrypickIntro, cherrypickFixed)
	default:
		affectedCommits = repo.AffectedSingleBranch(ctx, se)
	}

	cherryPickedEvents := make([]*pb.Event, 0, len(cherrypicks.Introduced)+len(cherrypicks.Fixed)+len(cherrypicks.Limit))
	for _, h := range cherrypicks.Introduced {
		cherryPickedEvents = append(cherryPickedEvents, &pb.Event{
			EventType: pb.EventType_INTRODUCED,
			Hash:      h,
		})
	}
	for _, h := range cherrypicks.Fixed {
		cherryPickedEvents = append(cherryPickedEvents, &pb.Event{
			EventType: pb.EventType_FIXED,
			Hash:      h,
		})
	}
	for _, h := range cherrypicks.Limit {
		cherryPickedEvents = append(cherryPickedEvents, &pb.Event{
			EventType: pb.EventType_LIMIT,
			Hash:      h,
		})
	}

	resp := &pb.AffectedCommitsResponse{
		Commits:            make([]*pb.Commit, 0, len(affectedCommits)),
		Tags:               make([]*pb.Ref, 0),
		CherryPickedEvents: cherryPickedEvents,
	}
	for _, c := range affectedCommits {
		resp.Commits = append(resp.Commits, &pb.Commit{
			Hash: c.Hash[:],
		})
		for _, tag := range c.Tags {
			resp.Tags = append(resp.Tags, &pb.Ref{
				Label: tag,
				Hash:  c.Hash[:],
			})
		}
	}

	out, err := marshalResponse(r, resp)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshaling affected commits", slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Error marshaling affected commits: %v", err), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(out); err != nil {
		logger.ErrorContext(ctx, "Error writing response", slog.Any("error", err))
	}
	logger.InfoContext(ctx, "Request completed successfully: /affected-commits", slog.Duration("duration", time.Since(start)))
}

func makeTagsResponse(tagsMap map[string]SHA1) *pb.TagsResponse {
	resp := &pb.TagsResponse{
		Tags: make([]*pb.Ref, 0, len(tagsMap)),
	}
	for tag, hash := range tagsMap {
		resp.Tags = append(resp.Tags, &pb.Ref{
			Label: tag,
			Hash:  hash[:],
		})
	}

	return resp
}

func tagsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	repoURL, err := prepareURL(r, r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), urlKey, repoURL)
	logger.InfoContext(ctx, "Received request: /tags")

	// Previously cached invalid repo (does not exist or does not have tags)
	// Get() will not return if the entry is past its TTL, so we can safely return the same http status code as is.
	if code, found := invalidRepoCache.Get(repoURL); found {
		logger.InfoContext(ctx, "Invalid repo cache hit", slog.Int("code", code))
		w.WriteHeader(code)

		return
	}

	var tagsMap map[string]SHA1

	// If repository is recently loaded, we can return the tags directly from the cached repo
	if cachedRepo, found := repoCache.Get(repoURL); found {
		logger.InfoContext(ctx, "Repo cache hit, returning cached tags")
		tagsMap = make(map[string]SHA1)
		for tag, idx := range cachedRepo.tagToCommit {
			tagsMap[tag] = cachedRepo.commits[idx].Hash
		}
	} else {
		repo := NewRepository(repoURL)

		// If repoPath is not empty, it means there is a local git directory for this repo on disk
		// We want to use show-ref instead of ls-remote because it's faster and we don't have to worry about rate limits
		if repo.repoPath != "" {
			logger.DebugContext(ctx, "Local repo found, using show-ref")
			if _, errFetch, _ := gFetch.Do(repoURL, func() (any, error) {
				return nil, FetchRepo(ctx, repoURL, false)
			}); errFetch != nil {
				logger.ErrorContext(ctx, "Error fetching repo", slog.Any("error", errFetch))
				if isAuthError(errFetch) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusForbidden, 1, invalidRepoTTL)
					http.Error(w, fmt.Sprintf("Error fetching repository: %v", errFetch), http.StatusForbidden)

					return
				}
				if isNotFoundError(errFetch) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusNotFound, 1, invalidRepoTTL)
					http.Error(w, fmt.Sprintf("Error fetching repository: %v", errFetch), http.StatusNotFound)

					return
				}
				http.Error(w, "Error fetching repository", http.StatusInternalServerError)

				return
			}

			tagsMapAny, errLocal, _ := gLocalTags.Do(repoURL, func() (any, error) {
				return repo.GetLocalTags(ctx)
			})
			if errLocal != nil {
				logger.ErrorContext(ctx, "Error parsing local tags", slog.Any("error", errLocal))
				http.Error(w, "Error parsing local tags", http.StatusInternalServerError)

				return
			}
			tagsMap = tagsMapAny.(map[string]SHA1)
		} else {
			// If repo is not on disk, we use ls-remote to get the tags instead
			logger.DebugContext(ctx, "Local repo not found, using ls-remote")
			tagsMapAny, errLsRemote, _ := gLsRemote.Do(repoURL, func() (any, error) {
				return repo.GetRemoteTags(ctx)
			})
			if errLsRemote != nil {
				if isAuthError(errLsRemote) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusForbidden, 1, invalidRepoTTL)
					http.Error(w, fmt.Sprintf("Repository authentication failed: %v", errLsRemote), http.StatusForbidden)

					return
				}
				if isNotFoundError(errLsRemote) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusNotFound, 1, invalidRepoTTL)
					http.Error(w, "Repository not found", http.StatusNotFound)

					return
				}
				logger.ErrorContext(ctx, "Error running git ls-remote", slog.Any("error", errLsRemote))
				http.Error(w, "Error listing remote tags", http.StatusInternalServerError)

				return
			}
			tagsMap = tagsMapAny.(map[string]SHA1)
		}
	}

	if len(tagsMap) == 0 {
		logger.InfoContext(ctx, "No tags in repository")
		invalidRepoCache.SetWithTTL(repoURL, http.StatusNoContent, 1, invalidRepoTTL)
		w.WriteHeader(http.StatusNoContent)

		return
	}

	resp := makeTagsResponse(tagsMap)
	out, err := marshalResponse(r, resp)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshaling tags response", slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Error marshaling tags response: %v", err), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(out); err != nil {
		logger.ErrorContext(ctx, "Error writing tags response", slog.Any("error", err))
	}
	logger.InfoContext(ctx, "Request completed successfully: /tags", slog.Duration("duration", time.Since(start)))
}
