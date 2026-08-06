package datastore

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

const defaultCacheTTL = 5 * time.Minute

type allowlistCacheData struct {
	mu          sync.RWMutex
	urlCache    map[string]struct{}
	regexCache  map[string]*regexp.Regexp
	lastFetched time.Time
}

var allowlistCache = &allowlistCacheData{
	urlCache:   make(map[string]struct{}),
	regexCache: make(map[string]*regexp.Regexp),
}

// For testing purposes
func resetAllowlistCache() {
	allowlistCache.mu.Lock()
	defer allowlistCache.mu.Unlock()
	allowlistCache.urlCache = make(map[string]struct{})
	allowlistCache.regexCache = make(map[string]*regexp.Regexp)
	allowlistCache.lastFetched = time.Time{}
}

// RepoCABStore handles Datastore persistence and caching for the repository Consider All Branches allowlist.
type RepoCABStore struct {
	client *datastore.Client
}

var _ models.RepoCABStore = (*RepoCABStore)(nil)

// NewRepoCABStore returns a new RepoCABStore instance.
func NewRepoCABStore(client *datastore.Client) *RepoCABStore {
	return &RepoCABStore{client: client}
}

// ShouldConsiderAllBranches returns true if the repoURL matches any pattern or url in the cab allowlist.
func (s *RepoCABStore) ShouldConsiderAllBranches(ctx context.Context, repoURL string) (bool, error) {
	if repoURL == "" || s.client == nil {
		return false, nil
	}

	normalized := normalizeRepo(repoURL)
	if normalized == "" {
		return false, nil
	}

	// 1. URL matching
	matchedURL, err := s.matchURL(ctx, normalized)
	if err != nil {
		return false, err
	}
	if matchedURL {
		return true, nil
	}

	// 2. Regex matching
	matchedPattern, err := s.matchPattern(ctx, repoURL, normalized)
	if err != nil {
		return false, err
	}

	return matchedPattern, nil
}

// matchURL checks if the repo URL matches an exact URL allowlist entry in Datastore cache.
func (s *RepoCABStore) matchURL(ctx context.Context, repo string) (bool, error) {
	if err := s.loadCache(ctx); err != nil {
		return false, err
	}

	allowlistCache.mu.RLock()
	defer allowlistCache.mu.RUnlock()

	_, ok := allowlistCache.urlCache[repo]

	return ok, nil
}

// matchPattern checks if the repo URL matches any cached compiled regex pattern.
func (s *RepoCABStore) matchPattern(ctx context.Context, repoURL, normalizedRepo string) (bool, error) {
	if err := s.loadCache(ctx); err != nil {
		return false, err
	}

	allowlistCache.mu.RLock()
	defer allowlistCache.mu.RUnlock()

	for _, re := range allowlistCache.regexCache {
		if re.MatchString(repoURL) || (normalizedRepo != "" && re.MatchString(normalizedRepo)) {
			return true, nil
		}
	}

	return false, nil
}

// loadCache retrieves all allowlist entries from Datastore, using in-memory global caching for URLs and regexes.
func (s *RepoCABStore) loadCache(ctx context.Context) error {
	// Fast path: check cache validity under read lock.
	allowlistCache.mu.RLock()
	if allowlistCache.urlCache != nil && allowlistCache.regexCache != nil && time.Since(allowlistCache.lastFetched) < defaultCacheTTL {
		allowlistCache.mu.RUnlock()
		return nil
	}
	allowlistCache.mu.RUnlock()

	allowlistCache.mu.Lock()
	defer allowlistCache.mu.Unlock()

	// Re-check if cache is valid in case another goroutine refreshed it while we were waiting for write lock
	if allowlistCache.urlCache != nil && allowlistCache.regexCache != nil && time.Since(allowlistCache.lastFetched) < defaultCacheTTL {
		return nil
	}

	var entries []RepoConsiderAllBranchesAllowList
	query := datastore.NewQuery("RepoConsiderAllBranchesAllowList")
	if _, err := s.client.GetAll(ctx, query, &entries); err != nil {
		return fmt.Errorf("failed fetching RepoConsiderAllBranchesAllowList entities: %w", err)
	}

	newURLCache := make(map[string]struct{})
	newRegexCache := make(map[string]*regexp.Regexp)

	for _, entry := range entries {
		switch entry.Type {
		case "regex":
			if entry.Value == "" {
				continue
			}
			re, ok := allowlistCache.regexCache[entry.Value]
			if !ok {
				var err error
				re, err = regexp.Compile(entry.Value)
				if err != nil {
					logger.WarnContext(ctx, "Failed to compile RepoConsiderAllBranchesAllowList regex entry", slog.String("value", entry.Value), slog.Any("error", err))
					continue
				}
			}
			newRegexCache[entry.Value] = re

		default: // URL exact match entries
			if entry.Value == "" {
				continue
			}
			newURLCache[entry.Value] = struct{}{}
		}
	}

	allowlistCache.urlCache = newURLCache
	allowlistCache.regexCache = newRegexCache
	allowlistCache.lastFetched = time.Now()

	return nil
}
