package main

import (
	"errors"
	"os"
	"path/filepath"
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

func TestExtractHTTPStatusCode(t *testing.T) {
	tests := []struct {
		err      error
		expected int
	}{
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), 429},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), 403},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 404"), 404},
		{errors.New("error: RPC failed; HTTP 500 curl 22 The requested URL returned error: 500"), 500},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 502"), 502},
		{errors.New("fatal: repository not found"), 0},
		{nil, 0},
	}

	for _, tt := range tests {
		if result := extractHTTPStatusCode(tt.err); result != tt.expected {
			t.Errorf("extractHTTPStatusCode(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), true},
		{errors.New("fatal: remote error: GitLab is currently unable to handle this request due to load (ID a2b5c730282383b9-ORD)."), true}, //nolint:revive // Testing exact error message from remote git host
		{errors.New("fatal: You have exceeded a secondary rate limit"), true},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRateLimitError(tt.err); result != tt.expected {
			t.Errorf("isRateLimitError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRemoteHostError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://git.example.com/repo': The requested URL returned error: 500"), true},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 502"), true},
		{errors.New("fatal: unable to access 'https://git.example.com/repo/': Could not connect to server"), true},
		{errors.New("fatal: unable to access 'https://git.example.com/repo/': Connection reset by peer"), true},
		{errors.New("fatal: early EOF\nfatal: fetch-pack: invalid index-pack output"), true},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRemoteHostError(tt.err); result != tt.expected {
			t.Errorf("isRemoteHostError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled"), true},
		{errors.New("fatal: Authentication failed for 'https://github.com/example/repo.git/'"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isAuthError(tt.err); result != tt.expected {
			t.Errorf("isAuthError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsForbiddenError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), true},
		{errors.New("remote: 403 Forbidden"), true},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isForbiddenError(tt.err); result != tt.expected {
			t.Errorf("isForbiddenError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("remote: Repository not found"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 404"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRefNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("ref cannot be empty"), true},
		{errors.New("failed to resolve target ref 'non-existent-branch'"), true},
		{errors.New("git cat-file failed: fatal: not found or invalid"), true},
		{errors.New("fatal: Authentication failed"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRefNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isRefNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsFileNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("git cat-file failed: fatal: Not a valid object name 1234abcd"), true},
		{errors.New("file does not exist in commit"), true},
		{errors.New("fatal: Authentication failed"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isFileNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isFileNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
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

func TestRefreshRepo_InhibitRecloneOnRemoteError(t *testing.T) {
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
