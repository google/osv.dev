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

type regexCacheEntry struct {
	pattern *regexp.Regexp
	flags   models.RepoAllowListFlags
}

type allowListCache struct {
	mu          sync.RWMutex
	urlCache    map[string]models.RepoAllowListFlags
	regexCache  map[string]regexCacheEntry
	lastFetched time.Time
}

var cache = &allowListCache{
	urlCache:   make(map[string]models.RepoAllowListFlags),
	regexCache: make(map[string]regexCacheEntry),
}

// For testing purposes
func resetCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.urlCache = make(map[string]models.RepoAllowListFlags)
	cache.regexCache = make(map[string]regexCacheEntry)
	cache.lastFetched = time.Time{}
}

// RepoAllowListStore handles Datastore persistence and caching for the repository allowlist.
type RepoAllowListStore struct {
	client *datastore.Client
}

var _ models.RepoAllowListStore = (*RepoAllowListStore)(nil)

// NewRepoAllowListStore returns a new RepoAllowListStore instance.
func NewRepoAllowListStore(client *datastore.Client) *RepoAllowListStore {
	return &RepoAllowListStore{client: client}
}

// GetFlags returns the combined feature flags for the given repoURL.
func (s *RepoAllowListStore) GetFlags(ctx context.Context, repoURL string) (models.RepoAllowListFlags, error) {
	if repoURL == "" || s.client == nil {
		return models.RepoAllowListFlags{}, nil
	}

	normalized := normalizeRepo(repoURL)
	if normalized == "" {
		return models.RepoAllowListFlags{}, nil
	}

	if err := s.loadCache(ctx); err != nil {
		return models.RepoAllowListFlags{}, err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	// 1. Exact URL match takes precedence over regex patterns
	if flags, ok := cache.urlCache[normalized]; ok {
		return flags, nil
	}

	var res models.RepoAllowListFlags

	// 2. Regex pattern match (used when no exact URL match exists)
	for _, re := range cache.regexCache {
		// Try to match both the actual and normalized repoURL
		if re.pattern.MatchString(repoURL) || re.pattern.MatchString(normalized) {
			res.ConsiderAllBranches = res.ConsiderAllBranches || re.flags.ConsiderAllBranches
			res.CherrypicksIntroduced = res.CherrypicksIntroduced || re.flags.CherrypicksIntroduced
			res.CherrypicksFixed = res.CherrypicksFixed || re.flags.CherrypicksFixed
			res.CherrypicksLimit = res.CherrypicksLimit || re.flags.CherrypicksLimit
		}
	}

	return res, nil
}

// loadCache retrieves all allowlist entries from Datastore, caches the url and regexes.
func (s *RepoAllowListStore) loadCache(ctx context.Context) error {
	// Fast path: check cache validity under read lock.
	cache.mu.RLock()
	if cache.urlCache != nil && cache.regexCache != nil && time.Since(cache.lastFetched) < defaultCacheTTL {
		cache.mu.RUnlock()
		return nil
	}
	cache.mu.RUnlock()

	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Re-check if cache is valid in case another goroutine refreshed it while we were waiting for write lock
	if cache.urlCache != nil && cache.regexCache != nil && time.Since(cache.lastFetched) < defaultCacheTTL {
		return nil
	}

	var entries []RepoAllowList
	query := datastore.NewQuery("RepoAllowList")
	if _, err := s.client.GetAll(ctx, query, &entries); err != nil {
		return fmt.Errorf("failed fetching RepoAllowList entities: %w", err)
	}

	newURLCache := make(map[string]models.RepoAllowListFlags, len(entries))

	for _, entry := range entries {
		flags := models.RepoAllowListFlags{
			ConsiderAllBranches:   entry.ConsiderAllBranches,
			CherrypicksIntroduced: entry.CherrypicksIntroduced,
			CherrypicksFixed:      entry.CherrypicksFixed,
			CherrypicksLimit:      entry.CherrypicksLimit,
		}

		switch entry.Type {
		case "regex":
			if entry.Value == "" {
				continue
			}
			cached, ok := cache.regexCache[entry.Value]
			var re *regexp.Regexp
			if ok && cached.pattern != nil {
				re = cached.pattern
			} else {
				var err error
				re, err = regexp.Compile(entry.Value)
				if err != nil {
					logger.WarnContext(ctx, "Failed to compile RepoAllowList regex entry", slog.String("value", entry.Value), slog.Any("error", err))
					continue
				}
			}
			cache.regexCache[entry.Value] = regexCacheEntry{
				pattern: re,
				flags:   flags,
			}

		default: // URL exact match entries
			if entry.Value == "" {
				continue
			}
			newURLCache[entry.Value] = flags
			normValue := normalizeRepo(entry.Value)
			if normValue != "" {
				newURLCache[normValue] = flags
			}
		}
	}

	cache.urlCache = newURLCache
	cache.lastFetched = time.Now()

	return nil
}
