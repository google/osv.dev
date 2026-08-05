package datastore

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

const defaultCABCacheTTL = 5 * time.Minute

// RepoCABStore handles Datastore persistence and caching for the repository Consider All Branches allowlist.
type RepoCABStore struct {
	client   *datastore.Client
	cacheTTL time.Duration

	mu          sync.RWMutex
	urlCache    map[string]struct{}
	regexCache  []*regexp.Regexp
	lastFetched time.Time
}

var _ models.RepoCABStore = (*RepoCABStore)(nil)

// NewRepoCABStore returns a new RepoCABStore instance with default cache TTL (5 minutes).
func NewRepoCABStore(client *datastore.Client) *RepoCABStore {
	return NewRepoCABStoreWithTTL(client, defaultCABCacheTTL)
}

// NewRepoCABStoreWithTTL returns a new RepoCABStore instance with a specified cache TTL.
func NewRepoCABStoreWithTTL(client *datastore.Client, cacheTTL time.Duration) *RepoCABStore {
	return &RepoCABStore{
		client:   client,
		cacheTTL: cacheTTL,
	}
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

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.urlCache[repo]

	return ok, nil
}

// matchPattern checks if the repo URL matches any cached compiled regex pattern.
func (s *RepoCABStore) matchPattern(ctx context.Context, repoURL, normalizedRepo string) (bool, error) {
	if err := s.loadCache(ctx); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, re := range s.regexCache {
		if re.MatchString(repoURL) || (normalizedRepo != "" && re.MatchString(normalizedRepo)) {
			return true, nil
		}
	}

	return false, nil
}

// loadCache retrieves all allowlist entries from Datastore, using in-memory caching for URLs and regexes.
func (s *RepoCABStore) loadCache(ctx context.Context) error {
	// Fast path: check cache validity under read lock.
	s.mu.RLock()
	if s.urlCache != nil && s.regexCache != nil && time.Since(s.lastFetched) < s.cacheTTL {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check if cache is valid in case another goroutine refreshed it while we are waiting for write lock
	if s.urlCache != nil && s.regexCache != nil && time.Since(s.lastFetched) < s.cacheTTL {
		return nil
	}

	var entries []RepoConsiderAllBranchesAllowList
	query := datastore.NewQuery("RepoConsiderAllBranchesAllowList")
	if _, err := s.client.GetAll(ctx, query, &entries); err != nil {
		return fmt.Errorf("failed fetching RepoConsiderAllBranchesAllowList entities: %w", err)
	}

	urlCache := make(map[string]struct{})
	regexCache := make([]*regexp.Regexp, 0)

	for _, entry := range entries {
		switch entry.Type {
		case "regex":
			if entry.Value == "" {
				continue
			}
			re, err := regexp.Compile(entry.Value)
			if err != nil {
				// Skip invalid regex entries.
				continue
			}
			regexCache = append(regexCache, re)

		default: // URL exact match entries
			if entry.Value == "" {
				continue
			}
			urlCache[entry.Value] = struct{}{}
		}
	}

	s.urlCache = urlCache
	s.regexCache = regexCache
	s.lastFetched = time.Now()

	return nil
}
