package main

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestRefreshRepo_DontRecloneOnRemoteError(t *testing.T) {
	setupTest(t)
	ctx := t.Context()

	repoURL := "https://example.com/test-repo.git"
	repoDirName := getRepoDirName(repoURL)
	repoPath := filepath.Join(gitStorePath, repoDirName)

	// Create a local git repo
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}
	if err := runCmd(ctx, repoPath, nil, "git", "init"); err != nil {
		t.Fatalf("git init failed: %v", err)
	}
	// Configure dummy git user
	_ = runCmd(ctx, repoPath, nil, "git", "config", "user.name", "Test")
	_ = runCmd(ctx, repoPath, nil, "git", "config", "user.email", "test@example.com")
	// Add remote origin pointing to an unreachable port (connection refused)
	if err := runCmd(ctx, repoPath, nil, "git", "remote", "add", "origin", "https://127.0.0.1:59999/repo.git"); err != nil {
		t.Fatalf("git remote add failed: %v", err)
	}

	// Create an initial commit
	dummyFile := filepath.Join(repoPath, "dummy.txt")
	if err := os.WriteFile(dummyFile, []byte("hello"), 0600); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := runCmd(ctx, repoPath, nil, "git", "add", "dummy.txt"); err != nil {
		t.Fatalf("git add failed: %v", err)
	}
	if err := runCmd(ctx, repoPath, nil, "git", "commit", "-m", "initial commit"); err != nil {
		t.Fatalf("git commit failed: %v", err)
	}

	// Verify .git exists
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		t.Fatalf(".git dir does not exist before refresh: %v", err)
	}

	// Attempt refreshRepo with forceUpdate = true
	// Remote fetch will fail with connection error (network error), but refreshRepo should inhibit reclone and return nil.
	err := refreshRepo(ctx, repoURL, true)
	if err != nil {
		t.Fatalf("refreshRepo failed unexpectedly: %v", err)
	}

	// Verify that the local repo was NOT deleted
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Errorf(".git directory was deleted by refreshRepo, expected it to be preserved")
	}

	// Verify dummy.txt is still there
	if _, err := os.Stat(dummyFile); os.IsNotExist(err) {
		t.Errorf("local repo contents were deleted by refreshRepo")
	}

	// Verify lastFetch was updated
	lastFetchMu.Lock()
	accessTime, ok := lastFetch[repoURL]
	lastFetchMu.Unlock()
	if !ok || accessTime.IsZero() {
		t.Errorf("lastFetch was not updated after successful fallback")
	}
}
