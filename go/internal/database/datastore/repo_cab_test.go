package datastore

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/testutils"
)

func TestRepoCABStore_ShouldConsiderAllBranches(t *testing.T) {
	resetAllowlistCache()
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRepoCABStore(dsClient)

	// Seed test data in Datastore with exact URLs and regexes for Consider All Branches (CAB)
	testEntries := []RepoConsiderAllBranchesAllowList{
		{Type: "url", Value: "github.com/google/osv.dev"},
		{Type: "url", Value: "github.com/foo/bar"},
		{Type: "regex", Value: "github\\.com/org-glob/.*"},
		{Type: "regex", Value: "^https?://github\\.com/regex-org/.*$"},
		{Type: "regex", Value: "github\\.com/test/repo-."},
	}

	keys := []*datastore.Key{
		datastore.NameKey("RepoConsiderAllBranchesAllowList", "github.com/google/osv.dev", nil),
		datastore.NameKey("RepoConsiderAllBranchesAllowList", "github.com/foo/bar", nil),
		datastore.NameKey("RepoConsiderAllBranchesAllowList", "github\\.com/org-glob/.*", nil),
		datastore.NameKey("RepoConsiderAllBranchesAllowList", "^https?://github\\.com/regex-org/.*$", nil),
		datastore.NameKey("RepoConsiderAllBranchesAllowList", "github\\.com/test/repo-.", nil),
	}

	if _, err := dsClient.PutMulti(ctx, keys, testEntries); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name    string
		repoURL string
		want    bool
	}{
		{
			name:    "Empty repo URL",
			repoURL: "",
			want:    false,
		},
		{
			name:    "Exact URL match",
			repoURL: "https://github.com/google/osv.dev.git",
			want:    true,
		},
		{
			name:    "Normalized lookup without .git suffix",
			repoURL: "https://github.com/google/osv.dev",
			want:    true,
		},
		{
			name:    "Normalized lookup with trailing slash",
			repoURL: "github.com/foo/bar/",
			want:    true,
		},
		{
			name:    "Normalized lookup with scheme matching host+path key",
			repoURL: "https://github.com/foo/bar",
			want:    true,
		},
		{
			name:    "Regex pattern matching repo in org",
			repoURL: "https://github.com/org-glob/sub-repo.git",
			want:    true,
		},
		{
			name:    "Regex pattern matching another repo in org",
			repoURL: "github.com/org-glob/another-repo",
			want:    true,
		},
		{
			name:    "Anchored regex pattern matching",
			repoURL: "https://github.com/regex-org/my-project",
			want:    true,
		},
		{
			name:    "Character class regex matching",
			repoURL: "https://github.com/test/repo-1",
			want:    true,
		},

		{
			name:    "Unlisted repo",
			repoURL: "https://github.com/unlisted/repo",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.ShouldConsiderAllBranches(ctx, tt.repoURL)
			if err != nil {
				t.Fatalf("ShouldConsiderAllBranches(%q) unexpected error: %v", tt.repoURL, err)
			}
			if got != tt.want {
				t.Errorf("ShouldConsiderAllBranches(%q) = %v, want %v", tt.repoURL, got, tt.want)
			}
		})
	}
}

func TestRepoCABStore_Caching(t *testing.T) {
	resetAllowlistCache()
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRepoCABStore(dsClient)

	regexEntry := RepoConsiderAllBranchesAllowList{
		Type:  "regex",
		Value: "github\\.com/cached-org/.*",
	}
	regexKey := datastore.NameKey("RepoConsiderAllBranchesAllowList", "github\\.com/cached-org/.*", nil)

	urlEntry := RepoConsiderAllBranchesAllowList{
		Type:  "url",
		Value: "github.com/cached-url/repo",
	}
	urlKey := datastore.NameKey("RepoConsiderAllBranchesAllowList", "github.com/cached-url/repo", nil)

	if _, err := dsClient.PutMulti(ctx, []*datastore.Key{regexKey, urlKey}, []RepoConsiderAllBranchesAllowList{regexEntry, urlEntry}); err != nil {
		t.Fatalf("Failed setup: %v", err)
	}

	// First match populates cache
	got, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-org/repo1")
	if err != nil || !got {
		t.Fatalf("Initial ShouldConsiderAllBranches failed for regex: got %v, err %v", got, err)
	}

	gotURL, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-url/repo")
	if err != nil || !gotURL {
		t.Fatalf("Initial ShouldConsiderAllBranches failed for url: got %v, err %v", gotURL, err)
	}

	// Check that cache is populated
	allowlistCache.mu.RLock()
	if len(allowlistCache.regexCache) != 1 {
		t.Errorf("expected 1 cached regex, got %d", len(allowlistCache.regexCache))
	}
	if _, ok := allowlistCache.urlCache["github.com/cached-url/repo"]; !ok {
		t.Errorf("expected urlCache to contain github.com/cached-url/repo")
	}
	allowlistCache.mu.RUnlock()

	// Delete from Datastore to test that cache hit still succeeds before TTL expires
	if err := dsClient.DeleteMulti(ctx, []*datastore.Key{regexKey, urlKey}); err != nil {
		t.Fatalf("Failed deleting keys: %v", err)
	}

	gotCached, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-org/repo2")
	if err != nil || !gotCached {
		t.Errorf("Expected cache hit for regex to succeed even after DB deletion, got %v, err %v", gotCached, err)
	}

	gotCachedURL, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-url/repo")
	if err != nil || !gotCachedURL {
		t.Errorf("Expected cache hit for url to succeed even after DB deletion, got %v, err %v", gotCachedURL, err)
	}

	// Simulate TTL expiry by setting lastFetched into the past
	allowlistCache.mu.Lock()
	allowlistCache.lastFetched = time.Now().Add(-6 * time.Minute)
	allowlistCache.mu.Unlock()

	// After TTL expiry, store should re-query DB and find no matches
	gotExpired, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-org/repo3")
	if err != nil {
		t.Fatalf("Unexpected error after cache expiry: %v", err)
	}
	if gotExpired {
		t.Errorf("Expected ShouldConsiderAllBranches for regex to return false after TTL expiry and DB deletion, got true")
	}

	gotExpiredURL, err := store.ShouldConsiderAllBranches(ctx, "https://github.com/cached-url/repo")
	if err != nil {
		t.Fatalf("Unexpected error after cache expiry for url: %v", err)
	}
	if gotExpiredURL {
		t.Errorf("Expected ShouldConsiderAllBranches for url to return false after TTL expiry and DB deletion, got true")
	}
}
