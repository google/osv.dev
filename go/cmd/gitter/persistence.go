package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	pb "github.com/google/osv.dev/go/cmd/gitter/pb/repository"
	"github.com/google/osv.dev/go/logger"
	"google.golang.org/protobuf/proto"
)

var (
	lastFetch   = make(map[string]time.Time)
	lastFetchMu sync.Mutex
	saveTimer   *time.Timer
)

func updateLastFetch(url string) {
	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	lastFetch[url] = time.Now()

	debounceSaveMap()
}

// deleteLastFetch removed an entry from the last fetch map for cases where the git dir does not exist
// This should not happen, but if it does, we should clean up the last fetch map to allow refetching
func deleteLastFetch(url string) {
	logger.Error("Cache says file should exist, but file does not exist.", slog.String("url", url))

	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	delete(lastFetch, url)

	debounceSaveMap()
}

func debounceSaveMap() {
	if saveTimer != nil {
		saveTimer.Stop()
	}
	saveTimer = time.AfterFunc(3*time.Second, func() {
		saveLastFetchMap()
	})
}

func saveLastFetchMap() {
	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	logger.Info("Saving lastFetch map", slog.String("path", persistencePath))

	data, err := json.Marshal(lastFetch)
	if err != nil {
		logger.Error("Error marshaling lastFetch map", slog.String("path", persistencePath), slog.Any("error", err))
		return
	}

	if err := os.WriteFile(persistencePath, data, 0600); err != nil {
		logger.Error("Error writing lastFetch map", slog.String("path", persistencePath), slog.Any("error", err))
	}
}

func loadLastFetchMap() {
	data, err := os.ReadFile(persistencePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Error reading lastFetch map", slog.String("path", persistencePath), slog.Any("error", err))
		}

		return
	}

	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	if err := json.Unmarshal(data, &lastFetch); err != nil {
		logger.Error("Error unmarshaling lastFetch map", slog.String("path", persistencePath), slog.Any("error", err))
	}

	logger.Info("Loaded lastFetch map", slog.Int("entry_count", len(lastFetch)))
}

func saveRepositoryCache(cachePath string, repo *Repository) error {
	logger.Info("Saving repository cache", slog.String("path", cachePath))

	cache := &pb.RepositoryCache{}
	for _, commit := range repo.commitDetails {
		cache.Commits = append(cache.Commits, &pb.CommitDetail{
			Hash:    commit.Hash[:],
			PatchId: commit.PatchID[:],
		})
	}

	data, err := proto.Marshal(cache)
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0600)
}

func loadRepositoryCache(cachePath string) (*pb.RepositoryCache, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	cache := &pb.RepositoryCache{}
	if err := proto.Unmarshal(data, cache); err != nil {
		return nil, err
	}

	return cache, nil
}
