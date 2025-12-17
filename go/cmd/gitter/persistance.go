package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/osv.dev/go/logger"
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
		saveMap()
	})
}

func saveMap() {
	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	logger.Info("Saving lastFetch map", slog.String("path", persistancePath))

	data, err := json.Marshal(lastFetch)
	if err != nil {
		logger.Error("Error marshaling lastFetch map", slog.String("path", persistancePath), slog.Any("error", err))
		return
	}

	if err := os.WriteFile(persistancePath, data, 0600); err != nil {
		logger.Error("Error writing lastFetch map", slog.String("path", persistancePath), slog.Any("error", err))
	}
}

func loadMap() {
	data, err := os.ReadFile(persistancePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Error reading lastFetch map", slog.String("path", persistancePath), slog.Any("error", err))
		}

		return
	}

	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()

	if err := json.Unmarshal(data, &lastFetch); err != nil {
		logger.Error("Error unmarshaling lastFetch map", slog.String("path", persistancePath), slog.Any("error", err))
	}
}
