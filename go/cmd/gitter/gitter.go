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
	urlKey   contextKey = "repoURL"
	refIDKey contextKey = "refID"
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
	"POST /file-diffs":       fileDiffsHandler,
	"POST /file-content":     fileContentHandler,
}

var (
	gFetch                  singleflight.Group
	gArchive                singleflight.Group
	gLoad                   singleflight.Group
	gLsRemote               singleflight.Group
	gLocalTags              singleflight.Group
	persistencePath         = filepath.Join(defaultGitterWorkDir, persistenceFileName)
	gitStorePath            = filepath.Join(defaultGitterWorkDir, gitStoreFileName)
	fetchTimeout            time.Duration
	reqConcurrencySemaphore chan struct{} // Request concurrency control
	// LRU cache for recently loaded repositories (key: repo URL)
	repoCache             *ristretto.Cache[string, *Repository]
	repoTTL               time.Duration
	repoCacheMaxCostBytes int64
	// Cache for invalid (does not exist, or does not have tags) repos
	// Maps repo URL to the HTTP status code (404 or 204) to return
	invalidRepoCache           *ristretto.Cache[string, int]
	invalidRepoTTL             time.Duration
	invalidRepoCacheMaxEntries int64

	// gitMirrors lists more performant mirrors for large/popular repos.
	// TODO: Don't hardcode this.
	gitMirrors = map[string]string{
		"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git":   "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux.git",
		"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git": "https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git",
	}
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

// runWithConcurrencyControl runs function f for request concurrency control.
// If skipReqConcurrencySemaphore is true, it executes f directly without waiting for a semaphore spot.
func runWithConcurrencyControl(ctx context.Context, skipReqConcurrencySemaphore bool, f func() (any, error)) (any, error) {
	if skipReqConcurrencySemaphore {
		return f()
	}

	select {
	case reqConcurrencySemaphore <- struct{}{}:
		defer func() { <-reqConcurrencySemaphore }()
		logger.DebugContext(ctx, "Concurrent requests", slog.Int("count", len(reqConcurrencySemaphore)))

		return f()
	case <-ctx.Done():
		logger.WarnContext(ctx, "Request cancelled while waiting for semaphore")
		return nil, ctx.Err()
	}
}

func isLocalRequest(req *http.Request) bool {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, it might be a raw IP (though rare in RemoteAddr),
		// or an empty string. Try parsing the whole string as an IP.
		host = req.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check if it's a loopback address (covers 127.0.0.0/8 and ::1)
	return ip.IsLoopback()
}

func prepareURL(req *http.Request, repoURL string) (string, error) {
	if repoURL == "" {
		return "", errors.New("missing url parameter")
	}

	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("error parsing url: %w", err)
	}

	// Removing trailing slashes
	u.Path = strings.TrimSuffix(u.Path, "/")

	// Convert git://github.com to https://github.com because it times out for some reason
	// git protocol on non-github urls works fine
	if u.Scheme == "git" && u.Host == "github.com" {
		u.Scheme = "https"
	}

	// Remove query and fragment from the URL
	u.RawQuery = ""
	u.Fragment = ""

	// normalize to https before checking for mirrors.
	mirrorKey := u.String()
	if u.Scheme == "http" {
		mirrorKey = "https" + u.String()[4:]
	}
	if mirror, ok := gitMirrors[mirrorKey]; ok {
		logger.Debug("Using mirror URL", slog.String("from", repoURL), slog.String("to", mirror))
		return mirror, nil
	}

	if !isLocalRequest(req) {
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "git" {
			return "", fmt.Errorf("unsupported protocol: %s", u.Scheme)
		}
	}

	logger.Debug("Prepared URL", slog.String("from", repoURL), slog.String("to", u.String()))

	return u.String(), nil
}

func logRequestCompletion(ctx context.Context, endpoint string, start time.Time, statusCode int) {
	logger.InfoContext(ctx, "Request completed",
		slog.String("endpoint", endpoint),
		slog.Int("status", statusCode),
		slog.Duration("duration", time.Since(start)),
	)
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
		strings.Contains(errString, "Authentication failed")
}

func isForbiddenError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(errString, "The requested URL returned error: 403")
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()

	return strings.Contains(strings.ToLower(errString), "repository") && strings.Contains(strings.ToLower(errString), "not found")
}

func isRefNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())

	return strings.Contains(s, "not found or invalid") ||
		strings.Contains(s, "failed to resolve target ref") ||
		strings.Contains(s, "failed to run git rev-parse") ||
		strings.Contains(s, "ref cannot be empty")
}

func isFileNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())

	return strings.Contains(s, "git cat-file failed") ||
		strings.Contains(s, "invalid object name") ||
		strings.Contains(s, "does not exist in")
}

// Helper function to unmarshal request body based on Content-Type (protobuf or JSON)
func unmarshalRequest(req *http.Request, msg proto.Message) error {
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	contentType := req.Header.Get("Content-Type")
	if contentType == "application/json" {
		return protojson.Unmarshal(data, msg)
	}
	// Default to protobuf
	return proto.Unmarshal(data, msg)
}

// Helper function to marshal and write response body based on Content-Type (protobuf or JSON)
func writeResponse(w http.ResponseWriter, req *http.Request, msg proto.Message) error {
	contentType := req.Header.Get("Content-Type")
	var out []byte
	var err error
	if contentType == "application/json" {
		out, err = protojson.Marshal(msg)
	} else {
		out, err = proto.Marshal(msg)
	}
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(out)
	return err
}

func main() {
	logger.InitGlobalLogger()
	logger.RegisterContextKey(urlKey, "repoURL")
	logger.RegisterContextKey(refIDKey, "refID")
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

	reqConcurrencySemaphore = make(chan struct{}, *concurrentLimit)

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

func gitHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/git", start, statusCode) }()

	repoURL, err := prepareURL(req, req.URL.Query().Get("url"))
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	forceUpdate := req.URL.Query().Get("force-update") == "true"

	refID := req.URL.Query().Get("ref_id")
	ctx = context.WithValue(ctx, urlKey, repoURL)
	ctx = context.WithValue(ctx, refIDKey, refID)
	logger.DebugContext(ctx, "Received request: /git", slog.Bool("forceUpdate", forceUpdate), slog.String("remoteAddr", req.RemoteAddr))

	// Fetch repo first
	if _, err := SyncRepoOnDisk(ctx, repoURL, FetchOptions{ForceUpdate: forceUpdate, SkipReqConcurrencySemaphore: true}); err != nil {
		if isAuthError(err) || isForbiddenError(err) {
			statusCode = http.StatusForbidden
		} else if isNotFoundError(err) {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), statusCode)

		return
	}

	// Archive repo
	fileDataAny, err, _ := gArchive.Do(repoURL, func() (any, error) {
		return runWithConcurrencyControl(ctx, true, func() (any, error) {
			return ArchiveRepo(ctx, repoURL)
		})
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error archiving blob", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error archiving blob: %v", err), statusCode)

		return
	}
	fileData := fileDataAny.([]byte)

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", "attachment; filename=\"git-blob.zst\"")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, bytes.NewReader(fileData)); err != nil {
		logger.ErrorContext(ctx, "Error copying file", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, "Error copying file", statusCode)

		return
	}
}

func cacheHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/cache", start, statusCode) }()

	body := &pb.CacheRequest{}
	if err := unmarshalRequest(req, body); err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), statusCode)

		return
	}

	repoURL, err := prepareURL(req, body.GetUrl())
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	refID := body.GetRefId()
	ctx = context.WithValue(ctx, urlKey, repoURL)
	ctx = context.WithValue(ctx, refIDKey, refID)
	logger.DebugContext(ctx, "Received request: /cache")

	if _, err := LoadRepo(ctx, repoURL, FetchOptions{ForceUpdate: body.GetForceUpdate(), SkipReqConcurrencySemaphore: true}); err != nil {
		if isAuthError(err) || isForbiddenError(err) {
			statusCode = http.StatusForbidden
		} else if isNotFoundError(err) {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, fmt.Sprintf("Error getting repo: %v", err), statusCode)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func affectedCommitsHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/affected-commits", start, statusCode) }()

	body := &pb.AffectedCommitsRequest{}
	if err := unmarshalRequest(req, body); err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), statusCode)

		return
	}

	repoURL, err := prepareURL(req, body.GetUrl())
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	se, err := separateEvents(body.GetEvents())
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

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

	refID := body.GetRefId()
	ctx = context.WithValue(ctx, urlKey, repoURL)
	ctx = context.WithValue(ctx, refIDKey, refID)
	logger.DebugContext(ctx, "Received request: /affected-commits",
		slog.Any("introduced", se.Introduced),
		slog.Any("fixed", se.Fixed),
		slog.Any("last_affected", se.LastAffected),
		slog.Any("limit", se.Limit),
		slog.Bool("cherrypickIntro", cherrypickIntro),
		slog.Bool("cherrypickFixed", cherrypickFixed),
		slog.Bool("cherrypickLimit", cherrypickLimit),
		slog.Bool("considerAllBranches", considerAllBranches),
	)

	repo, err := LoadRepo(ctx, repoURL, FetchOptions{ForceUpdate: body.GetForceUpdate(), SkipReqConcurrencySemaphore: false})
	if err != nil {
		if isAuthError(err) || isForbiddenError(err) {
			statusCode = http.StatusForbidden
		} else if isNotFoundError(err) {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, fmt.Sprintf("Error getting repo: %v", err), statusCode)

		return
	}

	var affectedCommits []*Commit
	var cherrypicks cherrypickedHashes

	switch {
	case len(se.Limit) > 0:
		affectedCommits, cherrypicks = repo.Limit(ctx, se, cherrypickIntro, cherrypickLimit)
	case considerAllBranches || (len(se.Fixed) == 0 && len(se.LastAffected) == 0):
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

	if err := writeResponse(w, req, resp); err != nil {
		logger.ErrorContext(ctx, "Error writing affected commits response", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error writing affected commits response: %v", err), statusCode)
	}
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

func tagsHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/tags", start, statusCode) }()

	repoURL, err := prepareURL(req, req.URL.Query().Get("url"))
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	refID := req.URL.Query().Get("ref_id")
	ctx = context.WithValue(ctx, urlKey, repoURL)
	ctx = context.WithValue(ctx, refIDKey, refID)
	logger.DebugContext(ctx, "Received request: /tags")

	// Previously cached invalid repo (does not exist or does not have tags)
	// Get() will not return if the entry is past its TTL, so we can safely return the same http status code as is.
	if code, found := invalidRepoCache.Get(repoURL); found {
		logger.DebugContext(ctx, "Invalid repo cache hit", slog.Int("code", code))
		statusCode = code
		w.WriteHeader(code)

		return
	}

	var tagsMap map[string]SHA1

	// If repository is recently loaded, we can return the tags directly from the cached repo
	if cachedRepo, found := repoCache.Get(repoURL); found {
		logger.DebugContext(ctx, "Repo cache hit, returning cached tags")
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
			if _, errFetch := SyncRepoOnDisk(ctx, repoURL, FetchOptions{ForceUpdate: false, SkipReqConcurrencySemaphore: false}); errFetch != nil {
				logger.ErrorContext(ctx, "Error fetching repo", slog.Any("error", errFetch))
				if isAuthError(errFetch) || isForbiddenError(errFetch) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusForbidden, 1, invalidRepoTTL)
					statusCode = http.StatusForbidden
					http.Error(w, fmt.Sprintf("Error fetching repository: %v", errFetch), statusCode)

					return
				}
				if isNotFoundError(errFetch) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusNotFound, 1, invalidRepoTTL)
					statusCode = http.StatusNotFound
					http.Error(w, fmt.Sprintf("Error fetching repository: %v", errFetch), statusCode)

					return
				}
				statusCode = http.StatusInternalServerError
				http.Error(w, "Error fetching repository", statusCode)

				return
			}

			tagsMapAny, errLocal, _ := gLocalTags.Do(repoURL, func() (any, error) {
				return repo.GetLocalTags(ctx)
			})
			if errLocal != nil {
				logger.ErrorContext(ctx, "Error parsing local tags", slog.Any("error", errLocal))
				statusCode = http.StatusInternalServerError
				http.Error(w, "Error parsing local tags", statusCode)

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
				if isAuthError(errLsRemote) || isForbiddenError(errLsRemote) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusForbidden, 1, invalidRepoTTL)
					statusCode = http.StatusForbidden
					http.Error(w, fmt.Sprintf("Repository authentication failed: %v", errLsRemote), statusCode)

					return
				}
				if isNotFoundError(errLsRemote) {
					invalidRepoCache.SetWithTTL(repoURL, http.StatusNotFound, 1, invalidRepoTTL)
					statusCode = http.StatusNotFound
					http.Error(w, "Repository not found", statusCode)

					return
				}
				logger.ErrorContext(ctx, "Error running git ls-remote", slog.Any("error", errLsRemote))
				statusCode = http.StatusInternalServerError
				http.Error(w, "Error listing remote tags", statusCode)

				return
			}
			tagsMap = tagsMapAny.(map[string]SHA1)
		}
	}

	if len(tagsMap) == 0 {
		logger.InfoContext(ctx, "No tags in repository")
		invalidRepoCache.SetWithTTL(repoURL, http.StatusNoContent, 1, invalidRepoTTL)
		statusCode = http.StatusNoContent
		w.WriteHeader(statusCode)

		return
	}

	resp := makeTagsResponse(tagsMap)
	if err := writeResponse(w, req, resp); err != nil {
		logger.ErrorContext(ctx, "Error writing tags response", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error writing tags response: %v", err), statusCode)
	}
}

func fileDiffsHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/file-diffs", start, statusCode) }()

	body := &pb.FileDiffsRequest{}
	if err := unmarshalRequest(req, body); err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), statusCode)

		return
	}

	repoURL, err := prepareURL(req, body.GetUrl())
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	lastSyncedCommit := body.GetLastSyncedCommit()
	branch := body.GetBranch()

	ctx = context.WithValue(ctx, urlKey, repoURL)
	logger.DebugContext(ctx, "Received request: /file-diffs",
		slog.String("last_synced_commit", lastSyncedCommit),
		slog.String("branch", branch),
	)

	repo, err := SyncRepoOnDisk(ctx, repoURL, FetchOptions{ForceUpdate: true, SkipReqConcurrencySemaphore: true})
	if err != nil {
		if isAuthError(err) || isForbiddenError(err) {
			statusCode = http.StatusForbidden
		} else if isNotFoundError(err) {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, fmt.Sprintf("Error getting repo: %v", err), statusCode)

		return
	}

	latestCommit, changes, err := repo.ListFileDiffs(ctx, lastSyncedCommit, branch)
	if err != nil {
		if isRefNotFoundError(err) {
			statusCode = http.StatusBadRequest
			http.Error(w, fmt.Sprintf("Invalid commit or branch reference: %v", err), statusCode)

			return
		}
		logger.ErrorContext(ctx, "Error listing file diffs", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error listing file diffs: %v", err), statusCode)

		return
	}

	pbChanges := make([]*pb.FileChange, 0, len(changes))
	for _, c := range changes {
		pbChanges = append(pbChanges, &pb.FileChange{
			FromPath: c.From,
			ToPath:   c.To,
		})
	}

	resp := &pb.FileDiffsResponse{
		LatestCommit: latestCommit,
		Changes:      pbChanges,
	}

	if err := writeResponse(w, req, resp); err != nil {
		logger.ErrorContext(ctx, "Error writing diff response", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error writing diff response: %v", err), statusCode)
	}
}

func fileContentHandler(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	statusCode := http.StatusOK
	ctx := req.Context()
	defer func() { logRequestCompletion(ctx, "/file-content", start, statusCode) }()

	body := &pb.FileContentRequest{}
	if err := unmarshalRequest(req, body); err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, fmt.Sprintf("Error unmarshaling request: %v", err), statusCode)

		return
	}

	repoURL, err := prepareURL(req, body.GetUrl())
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, err.Error(), statusCode)

		return
	}

	commit := body.GetCommit()
	filePath := body.GetPath()
	if commit == "" || filePath == "" {
		statusCode = http.StatusBadRequest
		http.Error(w, "Missing commit or path", statusCode)

		return
	}

	ctx = context.WithValue(ctx, urlKey, repoURL)
	logger.DebugContext(ctx, "Received request: /file-content",
		slog.String("commit", commit),
		slog.String("path", filePath),
	)

	repo, err := SyncRepoOnDisk(ctx, repoURL, FetchOptions{ForceUpdate: false, SkipReqConcurrencySemaphore: true})
	if err != nil {
		if isAuthError(err) || isForbiddenError(err) {
			statusCode = http.StatusForbidden
		} else if isNotFoundError(err) {
			statusCode = http.StatusNotFound
		} else {
			statusCode = http.StatusInternalServerError
		}
		http.Error(w, fmt.Sprintf("Error getting repo: %v", err), statusCode)

		return
	}

	content, err := repo.GetFileContent(ctx, commit, filePath)
	if err != nil {
		if isRefNotFoundError(err) || isFileNotFoundError(err) {
			logger.DebugContext(ctx, "File content not found", slog.Any("error", err))
			statusCode = http.StatusNotFound
			http.Error(w, fmt.Sprintf("Error getting file content: %v", err), statusCode)

			return
		}
		logger.ErrorContext(ctx, "Error getting file content", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error getting file content: %v", err), statusCode)

		return
	}

	resp := &pb.FileContentResponse{
		Content: content,
	}

	if err := writeResponse(w, req, resp); err != nil {
		logger.ErrorContext(ctx, "Error writing file content response", slog.Any("error", err))
		statusCode = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Error writing file content response: %v", err), statusCode)
	}
}
