package main

import (
	"errors"
	"testing"
)

func TestIsIndexLockError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: Unable to create '/path/to/repo.git/index.lock': File exists"), true},
		{errors.New("some other error"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isIndexLockError(tt.err); result != tt.expected {
			t.Errorf("isIndexLockError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRefConflictError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("error: some local refs could not be updated; try running 'git remote prune origin' to remove any old, conflicting branches"), true},
		{errors.New("error: fetching ref refs/remotes/some-ref-name failed: refname conflict"), true},
		{errors.New("some other error"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRefConflictError(tt.err); result != tt.expected {
			t.Errorf("isRefConflictError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestSyncRepoOnDiskAndLoadRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	setupTest(t)

	url := "https://github.com/oliverchang/osv-test.git"

	// Test SyncRepoOnDisk with SkipReqConcurrencySemaphore: true
	// There's no easy way to test the semaphore skipping part, so we just test that it works.
	repoDisk, err := SyncRepoOnDisk(t.Context(), url, FetchOptions{ForceUpdate: false, SkipReqConcurrencySemaphore: true})
	if err != nil {
		t.Fatalf("SyncRepoOnDisk failed with SkipReqConcurrencySemaphore=true: %v", err)
	}
	if repoDisk == nil || repoDisk.repoPath == "" {
		t.Errorf("SyncRepoOnDisk returned invalid repository struct")
	}

	// Test LoadRepo with SkipReqConcurrencySemaphore: false
	repoLoaded, err := LoadRepo(t.Context(), url, FetchOptions{ForceUpdate: false, SkipReqConcurrencySemaphore: false})
	if err != nil {
		t.Fatalf("LoadRepo failed with SkipReqConcurrencySemaphore=false: %v", err)
	}
	if repoLoaded == nil || len(repoLoaded.commits) == 0 {
		t.Errorf("LoadRepo returned empty repository commits")
	}
}
