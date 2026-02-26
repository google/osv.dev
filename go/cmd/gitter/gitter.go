// Package main is the main package for gitter caching service
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "net/http/pprof" //nolint:gosec // This is a internal only service not public to the internet

	"github.com/google/osv.dev/go/logger"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/sync/singleflight"
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
	"GET /git":    gitHandler,
	"POST /cache": cacheHandler,
}

var (
	gFetch          singleflight.Group
	gArchive        singleflight.Group
	gLoad           singleflight.Group
	persistencePath = filepath.Join(defaultGitterWorkDir, persistenceFileName)
	gitStorePath    = filepath.Join(defaultGitterWorkDir, gitStoreFileName)
	fetchTimeout    time.Duration
	semaphore       chan struct{} // Request concurrency control
)

const shutdownTimeout = 10 * time.Second

// repoLocks is a map of per-repository RWMutexes, with url as the key.
// It coordinates access between write operations (FetchRepo) that modify the git directory on disk
// and read operations (ArchiveRepo, LoadRepository, etc).
// It mainly handles:
// - Ensuring reads and writes are mutually exclusive.
// - Allowing multiple concurrent reads.
var repoLocks sync.Map

func GetRepoLock(url string) *sync.RWMutex {
	lock, _ := repoLocks.LoadOrStore(url, &sync.RWMutex{})
	return lock.(*sync.RWMutex)
}

// runCmd executes a command with context cancellation handled by sending SIGINT.
// It logs cancellation errors separately as requested.
func runCmd(ctx context.Context, dir string, env []string, name string, args ...string) error {
	logger.DebugContext(ctx, "Running command", slog.String("cmd", name), slog.Any("args", args))
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

func getRepoDirName(url string) string {
	base := path.Base(url)
	base = filepath.Base(base)
	base = strings.TrimSuffix(base, ".git")
	hash := sha256.Sum256([]byte(url))

	return fmt.Sprintf("%s-%s", base, hex.EncodeToString(hash[:]))
}

func isAuthError(err error) bool {
	errString := err.Error()
	return strings.Contains(errString, "could not read Username") ||
		strings.Contains(errString, "Authentication failed") ||
		(strings.Contains(strings.ToLower(errString), "repository") && strings.Contains(strings.ToLower(errString), "not found"))
}

func isIndexLockError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(errString, "index.lock") && strings.Contains(errString, "File exists")
}

func FetchRepo(ctx context.Context, url string, forceUpdate bool) error {
	logger.InfoContext(ctx, "Starting fetch repo")
	start := time.Now()

	repoDirName := getRepoDirName(url)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	repoLock := GetRepoLock(url)
	repoLock.Lock()
	defer repoLock.Unlock()

	lastFetchMu.Lock()
	accessTime, ok := lastFetch[url]
	lastFetchMu.Unlock()

	// Check if we need to fetch
	if forceUpdate || !ok || time.Since(accessTime) > fetchTimeout {
		logger.InfoContext(ctx, "Fetching git blob", slog.Duration("sinceAccessTime", time.Since(accessTime)))
		if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
			// Clone
			err := runCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "clone", "--", url, repoPath)
			if err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// Fetch/Pull - implementing simple git pull for now, might need reset --hard if we want exact mirrors
			// For a generic "get latest", pull is usually sufficient if we treat it as read-only.
			// Ideally safely: git fetch origin && git reset --hard origin/HEAD
			err := runCmd(ctx, repoPath, nil, "git", "fetch", "origin")
			if err != nil {
				return fmt.Errorf("git fetch failed: %w", err)
			}
			err = runCmd(ctx, repoPath, nil, "git", "reset", "--hard", "origin/HEAD")
			if err != nil && isIndexLockError(err) {
				// index.lock exists, likely a previous git reset got terminated and wasn't cleaned up properly.
				// We can remove the file and retry the command
				logger.WarnContext(ctx, "index.lock exists, attempting to remove and retry")
				indexLockPath := filepath.Join(repoPath, ".git", "index.lock")
				if err := os.Remove(indexLockPath); err != nil {
					return fmt.Errorf("failed to remove index.lock in %s: %w", repoPath, err)
				}
				// One more attempt at git reset
				err = runCmd(ctx, repoPath, nil, "git", "reset", "--hard", "origin/HEAD")
			}
			if err != nil {
				return fmt.Errorf("git reset failed: %w", err)
			}
		}

		updateLastFetch(url)
	}

	// Double check if the git directory exist
	_, err := os.Stat(filepath.Join(repoPath, ".git"))
	if err != nil {
		if os.IsNotExist(err) {
			deleteLastFetch(url)
		}

		return fmt.Errorf("failed to read file: %w", err)
	}

	logger.InfoContext(ctx, "Fetch completed", slog.Duration("duration", time.Since(start)))

	return nil
}

func ArchiveRepo(ctx context.Context, url string) ([]byte, error) {
	repoDirName := getRepoDirName(url)
	repoPath := filepath.Join(gitStorePath, repoDirName)
	archivePath := repoPath + ".zst"

	repoLock := GetRepoLock(url)
	repoLock.RLock()
	defer repoLock.RUnlock()

	lastFetchMu.Lock()
	accessTime := lastFetch[url]
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
	workDir := flag.String("work_dir", defaultGitterWorkDir, "Work directory")
	flag.DurationVar(&fetchTimeout, "fetch_timeout", time.Hour, "Fetch timeout duration")
	concurrentLimit := flag.Int("concurrent_limit", 100, "Concurrent limit for unique requests")
	flag.Parse()
	semaphore = make(chan struct{}, *concurrentLimit)

	persistencePath = filepath.Join(*workDir, persistenceFileName)
	gitStorePath = filepath.Join(*workDir, gitStoreFileName)

	if err := os.MkdirAll(gitStorePath, 0755); err != nil {
		logger.Fatal("Failed to create git store path", slog.String("path", gitStorePath), slog.Any("error", err))
	}

	loadLastFetchMap()

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
	url := r.URL.Query().Get("url")
	if url == "" {
		http.Error(w, "Missing url parameter", http.StatusBadRequest)
		return
	}
	forceUpdate := r.URL.Query().Get("force-update") == "true"

	ctx := context.WithValue(r.Context(), urlKey, url)

	logger.InfoContext(ctx, "Received request: /git", slog.Bool("forceUpdate", forceUpdate), slog.String("remoteAddr", r.RemoteAddr))
	// If request came from a local ip, don't do the check
	if !isLocalRequest(r) {
		// Check if url starts with protocols: http(s)://, git://, ssh://, (s)ftp://
		if match, _ := regexp.MatchString("^(https?|git|ssh)://", url); !match {
			http.Error(w, "Invalid url parameter", http.StatusBadRequest)
			return
		}
	}

	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	case <-ctx.Done():
		logger.WarnContext(ctx, "Request cancelled while waiting for semaphore")
		http.Error(w, "Server context cancelled", http.StatusServiceUnavailable)

		return
	}
	logger.DebugContext(ctx, "Concurrent requests", slog.Int("count", len(semaphore)))

	// Fetch repo first
	// Keep the key as the url regardless of forceUpdate.
	// Occasionally this could be problematic if an existing unforce updated
	// query is already inplace, no force update will happen.
	// That is highly unlikely in our use case, as importer only queries
	// the repo once, and always with force update.
	// This is a tradeoff for simplicity to avoid having to setup locks per repo.
	// I can't change singleflight's interface
	_, err, _ := gFetch.Do(url, func() (any, error) {
		return nil, FetchRepo(ctx, url, forceUpdate)
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error fetching blob", slog.Any("error", err))
		if isAuthError(err) {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusForbidden)

			return
		}
		http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusInternalServerError)

		return
	}

	// Archive repo
	// I can't change singleflight's interface
	fileDataAny, err, _ := gArchive.Do(url, func() (any, error) {
		return ArchiveRepo(ctx, url)
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
	// POST requets body processing
	var body struct {
		URL         string `json:"url"`
		ForceUpdate bool   `json:"force_update"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding JSON: %v", err), http.StatusBadRequest)

		return
	}
	defer r.Body.Close()

	url := body.URL
	ctx := context.WithValue(r.Context(), urlKey, url)
	logger.InfoContext(ctx, "Received request: /cache")

	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	case <-ctx.Done():
		logger.WarnContext(ctx, "Request cancelled while waiting for semaphore")
		http.Error(w, "Server context cancelled", http.StatusServiceUnavailable)

		return
	}
	logger.DebugContext(ctx, "Concurrent requests", slog.Int("count", len(semaphore)))

	// Fetch repo if it's not fresh
	// I can't change singleflight's interface
	if _, err, _ := gFetch.Do(url, func() (any, error) {
		return nil, FetchRepo(ctx, url, body.ForceUpdate)
	}); err != nil {
		logger.ErrorContext(ctx, "Error fetching blob", slog.Any("error", err))
		if isAuthError(err) {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusForbidden)

			return
		}
		http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusInternalServerError)

		return
	}

	repoDirName := getRepoDirName(url)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	// I can't change singleflight's interface
	_, err, _ = gLoad.Do(repoPath, func() (any, error) {
		repoLock := GetRepoLock(url)
		repoLock.RLock()
		defer repoLock.RUnlock()

		return LoadRepository(ctx, repoPath)
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load repository", slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to load repository: %v", err), http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)
	logger.InfoContext(ctx, "Request completed successfully: /cache", slog.Duration("duration", time.Since(start)))
}
