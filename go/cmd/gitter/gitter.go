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
	"regexp"
	"strings"
	"syscall"
	"time"

	"runtime/pprof"

	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/singleflight"
)

// API Endpoints
var endpointHandlers = map[string]http.HandlerFunc{
	"GET /repo":              gitHandler,
	"POST /cache":            cacheHandler,
	"POST /affected-commits": affectCommitsHandler,
}

const defaultGitterWorkDir = "/work/gitter"
const persistenceFileName = "last-fetch.json"
const gitStoreFileName = "git-store"

var (
	gFetch          singleflight.Group
	gArchive        singleflight.Group
	gLoad           singleflight.Group
	persistencePath = path.Join(defaultGitterWorkDir, persistenceFileName)
	gitStorePath    = path.Join(defaultGitterWorkDir, gitStoreFileName)
	fetchTimeout    time.Duration
)

type Event struct {
	EventType string `json:"eventType"` // TODO: enum this
	Hash      string `json:"hash"`
}

const shutdownTimeout = 10 * time.Second

// runCmd executes a command with context cancellation handled by sending SIGINT.
// It logs cancellation errors separately as requested.
func runCmd(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	// Use SIGINT instead of SIGKILL for graceful shutdown of subprocesses
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGINT)
	}
	// Ensure it eventually dies if it ignores SIGINT
	cmd.WaitDelay = shutdownTimeout / 2

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			// Log separately if cancelled
			logger.Warn("Command cancelled", slog.String("cmd", name), slog.Any("err", ctx.Err()))
			return nil, fmt.Errorf("command %s cancelled: %w", name, ctx.Err())
		}

		return nil, fmt.Errorf("command %s failed, stdout: %s, stderr: %s", name, out, err)
	}

	return out, nil
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
		return cmd.Process.Signal(syscall.SIGINT)
	}
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

func fetchRepo(ctx context.Context, url string, forceUpdate bool) error {
	logger.Info("Starting fetch repo", slog.String("url", url))
	start := time.Now()

	repoDirName := getRepoDirName(url)
	repoPath := path.Join(gitStorePath, repoDirName)

	lastFetchMu.Lock()
	accessTime, ok := lastFetch[url]
	lastFetchMu.Unlock()

	// Check if we need to fetch
	if forceUpdate || !ok || time.Since(accessTime) > fetchTimeout {
		logger.Info("Fetching git blob", slog.String("url", url), slog.Duration("sinceAccessTime", time.Since(accessTime)))
		if _, err := os.Stat(path.Join(repoPath, ".git")); os.IsNotExist(err) {
			// Clone
			_, err := runCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "clone", "--", url, repoPath)
			if err != nil {
				return fmt.Errorf("git clone failed: %w", err)
			}
		} else {
			// Fetch/Pull - implementing simple git pull for now, might need reset --hard if we want exact mirrors
			// For a generic "get latest", pull is usually sufficient if we treat it as read-only.
			// Ideally safely: git fetch origin && git reset --hard origin/HEAD
			_, err := runCmd(ctx, repoPath, nil, "git", "fetch", "origin")
			if err != nil {
				return fmt.Errorf("git fetch failed: %w", err)
			}
			_, err = runCmd(ctx, repoPath, nil, "git", "reset", "--hard", "origin/HEAD")
			if err != nil {
				return fmt.Errorf("git reset failed: %w", err)
			}
		}

		updateLastFetch(url)
	}

	// Double check if the git directory exist
	_, err := os.Stat(path.Join(repoPath, ".git"))
	if err != nil {
		if os.IsNotExist(err) {
			deleteLastFetch(url)
		}
		return fmt.Errorf("failed to read file: %w", err)
	}

	logger.Info("Fetch completed", slog.Duration("duration", time.Since(start)))
	return nil
}

func archiveRepo(ctx context.Context, url string) ([]byte, error) {
	repoDirName := getRepoDirName(url)
	repoPath := path.Join(gitStorePath, repoDirName)
	archivePath := repoPath + ".zst"

	lastFetchMu.Lock()
	accessTime := lastFetch[url]
	lastFetchMu.Unlock()

	// Check if archive needs update
	// We update if archive does not exist OR if it is older than the last fetch
	stats, err := os.Stat(archivePath)
	if os.IsNotExist(err) || (err == nil && stats.ModTime().Before(accessTime)) {
		logger.Info("Archiving git blob", slog.String("url", url))
		// Archive
		// tar --zstd -cf <archivePath> -C "<gitStorePath>/<repoDirName>" .
		// using -C to archive the relative path so it unzips nicely
		_, err := runCmd(ctx, "", nil, "tar", "--zstd", "-cf", archivePath, "-C", path.Join(gitStorePath, repoDirName), ".")
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
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")

	port := flag.Int("port", 8888, "Listen port")
	workDir := flag.String("work_dir", defaultGitterWorkDir, "Work directory")
	flag.DurationVar(&fetchTimeout, "fetch_timeout", time.Hour, "Fetch timeout duration")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			logger.Error("could not create CPU profile", slog.Any("error", err))
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			logger.Error("could not start CPU profile", slog.Any("error", err))
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	persistencePath = path.Join(*workDir, persistenceFileName)
	gitStorePath = path.Join(*workDir, gitStoreFileName)

	if err := os.MkdirAll(gitStorePath, 0755); err != nil {
		logger.Error("Failed to create git store path", slog.String("path", gitStorePath), slog.Any("error", err))
		os.Exit(1)
	}

	loadLastFetchMap()

	// Create a context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for endpoint, handler := range endpointHandlers {
		http.HandleFunc(endpoint, handler)
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

	logger.Info("Received request", slog.String("url", url), slog.Bool("forceUpdate", forceUpdate), slog.String("remoteAddr", r.RemoteAddr))
	// If request came from a local ip, don't do the check
	if !isLocalRequest(r) {
		// Check if url starts with protocols: http(s)://, git://, ssh://, (s)ftp://
		if match, _ := regexp.MatchString("^(https?|git|ssh)://", url); !match {
			http.Error(w, "Invalid url parameter", http.StatusBadRequest)
			return
		}
	}

	// Fetch repo first
	// Keep the key as the url regardless of forceUpdate.
	// Occasionally this could be problematic if an existing unforce updated
	// query is already inplace, no force update will happen.
	// That is highly unlikely in our use case, as importer only queries
	// the repo once, and always with force update.
	// This is a tradeoff for simplicity to avoid having to setup locks per repo.
	//nolint:contextcheck // I can't change singleflight's interface
	if _, err, _ := gFetch.Do(url, func() (any, error) {
		return nil, fetchRepo(r.Context(), url, forceUpdate)
	}); err != nil {
		logger.Error("Error fetching blob", slog.String("url", url), slog.Any("error", err))
		if isAuthError(err) {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusInternalServerError)
		return
	}

	// Archive repo
	//nolint:contextcheck // I can't change singleflight's interface
	fileDataAny, err, _ := gArchive.Do(url, func() (any, error) {
		return archiveRepo(r.Context(), url)
	})
	if err != nil {
		logger.Error("Error archiving blob", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Error archiving blob: %v", err), http.StatusInternalServerError)
		return
	}
	fileData := fileDataAny.([]byte)

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", "attachment; filename=\"git-blob.zst\"")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, bytes.NewReader(fileData)); err != nil {
		logger.Error("Error copying file", slog.String("url", url), slog.Any("error", err))
		http.Error(w, "Error copying file", http.StatusInternalServerError)

		return
	}

	logger.Info("Request completed successfully", slog.String("url", url))
}

func cacheHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// POST requets body processing
	var body struct {
		URL string `json:"url"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	url := body.URL
	logger.Info("Received request: /cache", slog.String("url", url))

	// Fetch repo if it's not fresh
	_, err, _ = gFetch.Do(url, func() (any, error) {
		return nil, fetchRepo(r.Context(), url)
	})
	if err != nil {
		logger.Error("Failed to update repo", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to update repo: %v", err), http.StatusInternalServerError)
		return
	}

	repoDirName := getRepoDirName(url)
	repoPath := path.Join(gitStorePath, repoDirName)

	_, err, _ = gLoad.Do(repoPath, func() (any, error) {
		return LoadRepository(r.Context(), repoPath)
	})
	if err != nil {
		logger.Error("Failed to load repository", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to load repository: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	logger.Info("Request completed successfully: /cache", slog.String("url", url), slog.Duration("duration", time.Since(start)))
}

func affectCommitsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// POST requets body processing
	var body struct {
		URL               string  `json:"url"`
		Events            []Event `json:"events"`
		DetectCherrypicks bool    `json:"detect_cherrypicks"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	url := body.URL
	introduced := []SHA1{}
	fixed := []SHA1{}
	lastAffected := []SHA1{}
	limit := []SHA1{}
	cherrypick := body.DetectCherrypicks

	for _, event := range body.Events {
		hash, err := hex.DecodeString(event.Hash)
		if err != nil {
			logger.Error("Error parsing hash", slog.String("hash", event.Hash), slog.Any("error", err))
			continue
		}

		switch event.EventType {
		case "introduced":
			introduced = append(introduced, SHA1(hash))
		case "fixed":
			fixed = append(fixed, SHA1(hash))
		case "last_affected":
			lastAffected = append(lastAffected, SHA1(hash))
		case "limit":
			limit = append(limit, SHA1(hash))
		default:
			logger.Error("Invalid event type", slog.String("event_type", event.EventType))
			continue
		}
	}
	logger.Info("Received request: /affected-commits", slog.String("url", url), slog.Any("introduced", introduced), slog.Any("fixed", fixed), slog.Any("last_affected", lastAffected), slog.Any("limit", limit), slog.Bool("cherrypick", cherrypick))

	// Limit and fixed/last_affected shouldn't exist in the same request as it doesn't make sense
	if (len(fixed) > 0 || len(lastAffected) > 0) && len(limit) > 0 {
		http.Error(w, "Limit and fixed/last_affected shouldn't exist in the same request", http.StatusBadRequest)
		return
	}

	// Fetch repo if it's not fresh
	if _, err, _ := gFetch.Do(url, func() (any, error) {
		return nil, fetchRepo(r.Context(), url)
	}); err != nil {
		logger.Error("Failed to update repo", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to update repo: %v", err), http.StatusInternalServerError)
		return
	}

	repoDirName := getRepoDirName(url)
	repoPath := path.Join(gitStorePath, repoDirName)

	repoAny, err, _ := gLoad.Do(repoPath, func() (any, error) {
		return LoadRepository(r.Context(), repoPath)
	})
	if err != nil {
		logger.Error("Failed to load repository", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to load repository: %v", err), http.StatusInternalServerError)
		return
	}
	repo := repoAny.(*Repository)

	var affectedCommits []*Commit
	if len(limit) > 0 {
		affectedCommits = repo.Between(introduced, limit)
	} else {
		affectedCommits = repo.Affected(introduced, fixed, lastAffected, cherrypick)
	}

	if err != nil {
		logger.Error("Error processing affected commits", slog.String("url", url), slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Error processing affected commits: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(affectedCommits)
	logger.Info("Request completed successfully: /affected-commits", slog.String("url", url), slog.Duration("duration", time.Since(start)))
}
