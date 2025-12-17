// Package main is the main package for gitter caching service
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/singleflight"
)

const getGitEndpoint = "/getgit"
const defaultGitterWorkDir = "/work/gitter"
const persistanceFileName = "last-fetch.json"
const gitStoreFileName = "git-store"

var (
	g               singleflight.Group
	persistancePath = path.Join(defaultGitterWorkDir, persistanceFileName)
	gitStorePath    = path.Join(defaultGitterWorkDir, gitStoreFileName)
	fetchTimeout    time.Duration
)

func getRepoDirName(url string) string {
	base := path.Base(url)
	base = strings.TrimSuffix(base, ".git")
	hash := sha256.Sum256([]byte(url))

	return fmt.Sprintf("%s-%s", base, hex.EncodeToString(hash[:]))
}

func fetchBlob(ctx context.Context, url string) (*os.File, error) {
	repoDirName := getRepoDirName(url)
	repoPath := path.Join(gitStorePath, repoDirName)
	archivePath := repoPath + ".zst"

	lastFetchMu.Lock()
	accessTime, ok := lastFetch[url]
	lastFetchMu.Unlock()

	// Check if we need to fetch
	if !ok || time.Since(accessTime) > fetchTimeout {
		logger.Info("Fetching git blob", slog.String("url", url), slog.Duration("sinceAccessTime", time.Since(accessTime)))
		if _, err := os.Stat(path.Join(repoPath, ".git")); os.IsNotExist(err) {
			// Clone
			cmd := exec.Command("git", "clone", url, repoPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("git clone failed: %w, output: %s", err, out)
			}
		} else {
			// Fetch/Pull - implementing simple git pull for now, might need reset --hard if we want exact mirrors
			// For a generic "get latest", pull is usually sufficient if we treat it as read-only.
			// Ideally safely: git fetch origin && git reset --hard origin/HEAD
			cmd := exec.Command("git", "-C", repoPath, "fetch", "origin")
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("git fetch failed: %w, output: %s", err, out)
			}
			cmd = exec.Command("git", "-C", repoPath, "reset", "--hard", "origin/HEAD")
			if out, err := cmd.CombinedOutput(); err != nil {
				return nil, fmt.Errorf("git reset failed: %w, output: %s", err, out)
			}
		}

		logger.Info("Archiving git blob", slog.String("url", url))
		// Archive
		// tar --zstd -cf <archivePath> -C <gitStorePath> <repoDirName>
		// using -C to archive the relative path so it unzips nicely
		cmd := exec.Command("tar", "--zstd", "-cf", archivePath, "-C", path.Join(gitStorePath, repoDirName), ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("tar zstd failed: %w, output: %s", err, out)
		}

		updateLastFetch(url)
	}

	// If the context is cancelled, still do the fetching stuff, just don't bother returning the result
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	file, err := os.Open(archivePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			deleteLastFetch(url)
		}

		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return file, nil
}

func main() {
	port := flag.Int("port", 8888, "Listen port")
	workDir := flag.String("work_dir", defaultGitterWorkDir, "Work directory")
	flag.DurationVar(&fetchTimeout, "fetch_timeout", time.Hour, "Fetch timeout duration")
	flag.Parse()

	persistancePath = path.Join(*workDir, persistanceFileName)
	gitStorePath = path.Join(*workDir, gitStoreFileName)

	if err := os.MkdirAll(gitStorePath, 0755); err != nil {
		logger.Error("Failed to create git store path", slog.String("path", gitStorePath), slog.Any("error", err))
		os.Exit(1)
	}

	loadMap()

	http.HandleFunc(getGitEndpoint, func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "" {
			http.Error(w, "Missing url parameter", http.StatusBadRequest)
			return
		}

		logger.Info("Received request", slog.String("url", url))

		//nolint:contextcheck // I can't change singleflight's interface
		val, err, _ := g.Do(url, func() (any, error) {
			return fetchBlob(r.Context(), url)
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("Error fetching blob: %v", err), http.StatusInternalServerError)
			return
		}

		file := val.(*os.File)
		defer file.Close()

		w.Header().Set("Content-Type", "application/zstd")
		w.Header().Set("Content-Disposition", "attachment; filename=\"git-blob.zst\"")
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, file); err != nil {
			logger.Error("Error copying file", slog.String("url", url), slog.Any("error", err))
			http.Error(w, "Error copying file", http.StatusInternalServerError)

			return
		}
	})

	logger.Info("Gitter starting and listening", slog.Int("port", *port))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Error("Gitter failed to start", slog.Int("port", *port), slog.Any("error", err))
		os.Exit(1)
	}
}
