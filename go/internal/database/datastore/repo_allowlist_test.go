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

	urlKey := datastore.NameKey("RepoAllowList", "github.com/cached-url/repo", nil)
	urlEntry := RepoAllowList{
		Type:             "url",
		Value:            "github.com/cached-url/repo",
		CherrypicksFixed: true,
	}

	regexKey := datastore.NameKey("RepoAllowList", "github\\.com/cached-org/.*", nil)
	regexEntry := RepoAllowList{
		Type:                "regex",
		Value:               "github\\.com/cached-org/.*",
		ConsiderAllBranches: true,
	}

	if _, err := dsClient.PutMulti(ctx, []*datastore.Key{urlKey, regexKey}, []RepoAllowList{urlEntry, regexEntry}); err != nil {
		t.Fatalf("Failed setup: %v", err)
	}

	// 1. Initial call populates cache
	flags, err := store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil || !flags.CherrypicksFixed {
		t.Fatalf("Initial GetFlags failed: got %+v, err %v", flags, err)
	}

	// 2. Delete entry from Datastore; cache hit still succeeds before TTL expiry
	if err := dsClient.DeleteMulti(ctx, []*datastore.Key{urlKey, regexKey}); err != nil {
		t.Fatalf("Failed deleting keys: %v", err)
	}
	flags, err = store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil || !flags.CherrypicksFixed {
		t.Errorf("Expected cache hit before TTL expiry, got %+v, err %v", flags, err)
	}

	// 3. Expire TTL -> store re-queries DB and URL entry is cleared from urlCache
	cache.mu.Lock()
	cache.lastFetched = time.Now().Add(-6 * time.Minute)
	cache.mu.Unlock()

	flags, err = store.GetFlags(ctx, "https://github.com/cached-url/repo")
	if err != nil || flags.CherrypicksFixed {
		t.Errorf("Expected URL cache refresh after TTL expiry, got %+v, err %v", flags, err)
	}
}
