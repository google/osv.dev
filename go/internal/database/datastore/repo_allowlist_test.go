package datastore

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestRepoAllowListStore_GetFlags(t *testing.T) {
	resetCache()
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRepoAllowListStore(dsClient)

	// Seed test data in Datastore with exact URLs and regexes for RepoAllowList
	testEntries := []RepoAllowList{
		{Type: "url", Value: "github.com/google/osv.dev", ConsiderAllBranches: true, CherrypicksIntroduced: true, CherrypicksFixed: false, CherrypicksLimit: false},
		{Type: "url", Value: "github.com/foo/bar", ConsiderAllBranches: false, CherrypicksIntroduced: false, CherrypicksFixed: true, CherrypicksLimit: true},
		{Type: "url", Value: "github.com/all/flags", ConsiderAllBranches: true, CherrypicksIntroduced: true, CherrypicksFixed: true, CherrypicksLimit: true},
		{Type: "regex", Value: "github\\.com/org-glob/.*", ConsiderAllBranches: true, CherrypicksIntroduced: false, CherrypicksFixed: true, CherrypicksLimit: false},
		{Type: "regex", Value: "^https?://github\\.com/regex-intro/.*$", ConsiderAllBranches: false, CherrypicksIntroduced: true, CherrypicksFixed: false, CherrypicksLimit: true},
		{Type: "url", Value: "github.com/org-glob/override-repo", ConsiderAllBranches: false, CherrypicksIntroduced: true, CherrypicksFixed: false, CherrypicksLimit: false},
		{Type: "url", Value: "https://github.com/unnorm/repo.git", ConsiderAllBranches: false, CherrypicksIntroduced: false, CherrypicksFixed: false, CherrypicksLimit: true},
	}

	keys := []*datastore.Key{
		datastore.NameKey("RepoAllowList", "github.com/google/osv.dev", nil),
		datastore.NameKey("RepoAllowList", "github.com/foo/bar", nil),
		datastore.NameKey("RepoAllowList", "github.com/all/flags", nil),
		datastore.NameKey("RepoAllowList", "github\\.com/org-glob/.*", nil),
		datastore.NameKey("RepoAllowList", "^https?://github\\.com/regex-intro/.*$", nil),
		datastore.NameKey("RepoAllowList", "github.com/org-glob/override-repo", nil),
		datastore.NameKey("RepoAllowList", "https://github.com/unnorm/repo.git", nil),
	}

	if _, err := dsClient.PutMulti(ctx, keys, testEntries); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name      string
		repoURL   string
		wantFlags models.RepoAllowListFlags
	}{
		{
			name:      "Empty repo URL",
			repoURL:   "",
			wantFlags: models.RepoAllowListFlags{},
		},
		{
			name:    "Exact URL match (CAB and Intro enabled)",
			repoURL: "https://github.com/google/osv.dev.git",
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches:   true,
				CherrypicksIntroduced: true,
			},
		},
		{
			name:    "Normalized lookup (Fixed and Limit enabled)",
			repoURL: "https://github.com/foo/bar",
			wantFlags: models.RepoAllowListFlags{
				CherrypicksFixed: true,
				CherrypicksLimit: true,
			},
		},
		{
			name:    "All flags enabled",
			repoURL: "https://github.com/all/flags",
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches:   true,
				CherrypicksIntroduced: true,
				CherrypicksFixed:      true,
				CherrypicksLimit:      true,
			},
		},
		{
			name:    "Regex pattern match (CAB and Fixed enabled)",
			repoURL: "https://github.com/org-glob/sub-repo.git",
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches: true,
				CherrypicksFixed:    true,
			},
		},
		{
			name:    "Exact URL match takes precedence over regex match",
			repoURL: "https://github.com/org-glob/override-repo",
			wantFlags: models.RepoAllowListFlags{
				CherrypicksIntroduced: true,
			},
		},
		{
			name:    "Un-normalized Datastore URL entry matches normalized query",
			repoURL: "https://github.com/unnorm/repo",
			wantFlags: models.RepoAllowListFlags{
				CherrypicksLimit: true,
			},
		},
		{
			name:    "Regex pattern match (Intro and Limit enabled)",
			repoURL: "https://github.com/regex-intro/my-project",
			wantFlags: models.RepoAllowListFlags{
				CherrypicksIntroduced: true,
				CherrypicksLimit:      true,
			},
		},
		{
			name:      "Unlisted repo",
			repoURL:   "https://github.com/unlisted/repo",
			wantFlags: models.RepoAllowListFlags{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlags, err := store.GetFlags(ctx, tt.repoURL)
			if err != nil {
				t.Fatalf("GetFlags(%q) unexpected error: %v", tt.repoURL, err)
			}
			if gotFlags != tt.wantFlags {
				t.Errorf("GetFlags(%q) = %+v, want %+v", tt.repoURL, gotFlags, tt.wantFlags)
			}
		})
	}
}

func TestRepoAllowListStore_Caching(t *testing.T) {
	resetCache()
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRepoAllowListStore(dsClient)

	regexEntry := RepoAllowList{
		Type:                  "regex",
		Value:                 "github\\.com/cached-org/.*",
		ConsiderAllBranches:   true,
		CherrypicksIntroduced: true,
	}
	regexKey := datastore.NameKey("RepoAllowList", "github\\.com/cached-org/.*", nil)

	urlEntry := RepoAllowList{
		Type:             "url",
		Value:            "github.com/cached-url/repo",
		CherrypicksFixed: true,
		CherrypicksLimit: true,
	}
	urlKey := datastore.NameKey("RepoAllowList", "github.com/cached-url/repo", nil)

	if _, err := dsClient.PutMulti(ctx, []*datastore.Key{regexKey, urlKey}, []RepoAllowList{regexEntry, urlEntry}); err != nil {
		t.Fatalf("Failed setup: %v", err)
	}

	// First match populates cache
	flagsRegex, err := store.GetFlags(ctx, "https://github.com/cached-org/repo1")
	if err != nil || !flagsRegex.ConsiderAllBranches || !flagsRegex.CherrypicksIntroduced {
		t.Fatalf("Initial GetFlags failed for regex: got %+v, err %v", flagsRegex, err)
	}

	flagsURL, err := store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil || !flagsURL.CherrypicksFixed || !flagsURL.CherrypicksLimit {
		t.Fatalf("Initial GetFlags failed for url: got %+v, err %v", flagsURL, err)
	}

	// Check that cache is populated
	cache.mu.RLock()
	if len(cache.regexCache) != 1 {
		t.Errorf("expected 1 cached regex, got %d", len(cache.regexCache))
	}
	if flags, ok := cache.urlCache["github.com/cached-url/repo"]; !ok || !flags.CherrypicksFixed || !flags.CherrypicksLimit {
		t.Errorf("expected urlCache to contain github.com/cached-url/repo with CherrypicksFixed=true, CherrypicksLimit=true")
	}
	cache.mu.RUnlock()

	// Delete from Datastore to test that cache hit still succeeds before TTL expires
	if err := dsClient.DeleteMulti(ctx, []*datastore.Key{regexKey, urlKey}); err != nil {
		t.Fatalf("Failed deleting keys: %v", err)
	}

	flagsCachedRegex, err := store.GetFlags(ctx, "https://github.com/cached-org/repo2")
	if err != nil || !flagsCachedRegex.ConsiderAllBranches {
		t.Errorf("Expected cache hit for regex to succeed even after DB deletion, got %+v, err %v", flagsCachedRegex, err)
	}

	flagsCachedURL, err := store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil || !flagsCachedURL.CherrypicksFixed {
		t.Errorf("Expected cache hit for url to succeed even after DB deletion, got %+v, err %v", flagsCachedURL, err)
	}

	// Simulate TTL expiry by setting lastFetched into the past
	cache.mu.Lock()
	cache.lastFetched = time.Now().Add(-6 * time.Minute)
	cache.mu.Unlock()

	// After TTL expiry, store should re-query DB and find no matches
	flagsExpired, err := store.GetFlags(ctx, "https://github.com/cached-org/repo3")
	if err != nil {
		t.Fatalf("Unexpected error after cache expiry: %v", err)
	}
	if flagsExpired.ConsiderAllBranches || flagsExpired.CherrypicksIntroduced {
		t.Errorf("Expected GetFlags for regex to return zero flags after TTL expiry and DB deletion, got %+v", flagsExpired)
	}

	flagsExpiredURL, err := store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil {
		t.Fatalf("Unexpected error after cache expiry for url: %v", err)
	}
	if flagsExpiredURL.CherrypicksFixed || flagsExpiredURL.CherrypicksLimit {
		t.Errorf("Expected GetFlags for url to return zero flags after TTL expiry and DB deletion, got %+v", flagsExpiredURL)
	}
}
