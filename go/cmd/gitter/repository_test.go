package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A very simple test repository with 3 commits and 2 tags.
func setupTestRepo(t *testing.T) string {
	t.Helper()
	repoPath := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repoPath
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\nOutput: %s", args, err, out)
		}
	}

	runGit("init")

	// Commit 1
	os.WriteFile(filepath.Join(repoPath, "file1"), []byte("1"), 0644)
	runGit("add", "file1")
	runGit("commit", "-m", "commit 1")

	// Commit 2 + Tag
	os.WriteFile(filepath.Join(repoPath, "file2"), []byte("2"), 0644)
	runGit("add", "file2")
	runGit("commit", "-m", "commit 2")
	runGit("tag", "v1.0.0")

	// Commit 3 + Tag
	os.WriteFile(filepath.Join(repoPath, "file3"), []byte("3"), 0644)
	runGit("add", "file3")
	runGit("commit", "-m", "commit 3")
	runGit("tag", "v1.1.0")

	return repoPath
}

func TestBuildCommitGraph(t *testing.T) {
	repoPath := setupTestRepo(t)
	r := NewRepository(repoPath)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

	newCommits, err := r.buildCommitGraph(ctx, nil)

	if err != nil {
		t.Fatalf("buildCommitGraph failed: %v", err)
	}

	if len(newCommits) != 3 {
		t.Errorf("expected 3 new commits, got %d", len(newCommits))
	}

	if len(r.commitDetails) != 3 {
		t.Errorf("expected 3 commits with details, got %d", len(r.commitDetails))
	}

	if len(r.tagToCommit) != 2 {
		t.Errorf("expected 2 tags, got %d", len(r.tagToCommit))
	}
}

func TestCalculatePatchIDs(t *testing.T) {
	repoPath := setupTestRepo(t)
	r := NewRepository(repoPath)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

	newCommits, err := r.buildCommitGraph(ctx, nil)
	if err != nil {
		t.Fatalf("buildCommitGraph failed: %v", err)
	}

	err = r.calculatePatchIDs(ctx, newCommits)
	if err != nil {
		t.Fatalf("calculatePatchIDs failed: %v", err)
	}

	// Verify all commits have patch IDs
	for _, hash := range newCommits {
		details := r.commitDetails[hash]
		if details.PatchID == [20]byte{} {
			t.Errorf("missing patch ID for commit %x", hash)
		}
	}
}

func TestLoadRepository(t *testing.T) {
	repoPath := setupTestRepo(t)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

	// First loadRepository with a brand new repo
	r1, err := LoadRepository(ctx, repoPath)
	if err != nil {
		t.Fatalf("First LoadRepository failed: %v", err)
	}

	// Verify cache file is created
	cachePath := repoPath + ".pb"
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("expected cache file to be created")
	}

	// A second loadRepoistory has hit the test
	r2, err := LoadRepository(ctx, repoPath)
	if err != nil {
		t.Fatalf("Second LoadRepository failed: %v", err)
	}

	// Check that the two sets of Patch IDs are the same
	for hash, details := range r1.commitDetails {
		if details.PatchID != r2.commitDetails[hash].PatchID {
			t.Errorf("patch ID mismatch for commit %x", hash)
		}
	}
}
