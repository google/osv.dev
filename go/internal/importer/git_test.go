package importer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/google/osv.dev/go/internal/models"
)

func TestGitSourceRecord_Open(t *testing.T) {
	// Setup a temporary git repo
	dir, err := os.MkdirTemp("", "osv-git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Create a file
	filePath := filepath.Join(dir, "test.json")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
	if _, err := wt.Add("test.json"); err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}
	hash, err := wt.Commit("Init", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}
	commit, err := repo.CommitObject(hash)
	if err != nil {
		t.Fatalf("Failed to get commit: %v", err)
	}

	record := gitSourceRecord{
		repo: sharedRepo{
			Repository: repo,
			mu:         &sync.Mutex{},
		},
		commit: commit,
		path:   "test.json",
	}

	reader, err := record.Open(context.Background())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(data) != "data" {
		t.Errorf("Expected 'data', got '%s'", string(data))
	}
}

func TestHandleImportGit(t *testing.T) {
	// Setup a temporary git repo acting as the remote source
	remoteDir, err := os.MkdirTemp("", "osv-git-remote-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(remoteDir)

	remoteRepo, err := git.PlainInit(remoteDir, false)
	if err != nil {
		t.Fatalf("Failed to init remote repo: %v", err)
	}
	remoteWt, err := remoteRepo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get remote worktree: %v", err)
	}

	// Initial commit: ignored file and old file
	os.WriteFile(filepath.Join(remoteDir, "ignore.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(remoteDir, "CVE-A.json"), []byte("{}"), 0644)
	remoteWt.Add("ignore.json")
	remoteWt.Add("CVE-A.json")
	commitA, _ := remoteWt.Commit("Initial", &git.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})

	// Second commit: Modify old file, add new file
	os.WriteFile(filepath.Join(remoteDir, "CVE-A.json"), []byte(`{"modified": true}`), 0644)
	os.WriteFile(filepath.Join(remoteDir, "CVE-B.json"), []byte("{}"), 0644)
	remoteWt.Add("CVE-A.json")
	remoteWt.Add("CVE-B.json")
	commitB, _ := remoteWt.Commit("Second", &git.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]interface{}),
	}
	workDir, _ := os.MkdirTemp("", "osv-git-work-*")
	defer os.RemoveAll(workDir)

	config := Config{
		SourceRepoStore: mockStore,
		GitWorkDir:      workDir,
	}

	sourceRepo := &models.SourceRepository{
		Name:           "test-git-repo",
		Type:           models.SourceRepositoryTypeGit,
		Extension:      ".json",
		IgnorePatterns: []string{"ignore.*"},
		Git: &models.SourceRepoGit{
			URL:              remoteDir,
			LastSyncedCommit: commitA.String(),
		},
	}

	ch := make(chan SourceRecord, 10)
	err = handleImportGit(context.Background(), ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportGit failed: %v", err)
	}
	close(ch)

	var records []gitSourceRecord
	for r := range ch {
		records = append(records, r.(gitSourceRecord))
	}

	// We expect 2 records based on diff from commitA to commitB
	// CVE-A.json was modified, CVE-B.json was added.
	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}

	paths := make(map[string]bool)
	for _, r := range records {
		paths[r.path] = true
	}

	if !paths["CVE-A.json"] {
		t.Errorf("Expected CVE-A.json to be processed")
	}
	if !paths["CVE-B.json"] {
		t.Errorf("Expected CVE-B.json to be processed")
	}

	// Verify the LastSyncedCommit was updated
	if sourceRepo.Git.LastSyncedCommit != commitB.String() {
		t.Errorf("Expected LastSyncedCommit %s, got %s", commitB.String(), sourceRepo.Git.LastSyncedCommit)
	}
}

func TestHandleImportGit_Deletion(t *testing.T) {
	// Setup a temporary git repo acting as the remote source
	remoteDir, err := os.MkdirTemp("", "osv-git-remote-del-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(remoteDir)

	remoteRepo, err := git.PlainInit(remoteDir, false)
	if err != nil {
		t.Fatalf("Failed to init remote repo: %v", err)
	}
	remoteWt, err := remoteRepo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get remote worktree: %v", err)
	}

	// Initial commit: one file
	os.WriteFile(filepath.Join(remoteDir, "CVE-A.json"), []byte("{}"), 0644)
	remoteWt.Add("CVE-A.json")
	commitA, _ := remoteWt.Commit("Initial", &git.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})

	// Second commit: Delete the file
	_, _ = remoteWt.Remove("CVE-A.json")
	commitB, _ := remoteWt.Commit("Second (Delete)", &git.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]interface{}),
	}
	workDir, _ := os.MkdirTemp("", "osv-git-work-del-*")
	defer os.RemoveAll(workDir)

	config := Config{
		SourceRepoStore: mockStore,
		GitWorkDir:      workDir,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-git-repo",
		Type:      models.SourceRepositoryTypeGit,
		Extension: ".json",
		Git: &models.SourceRepoGit{
			URL:              remoteDir,
			LastSyncedCommit: commitA.String(),
		},
	}

	ch := make(chan SourceRecord, 10)
	err = handleImportGit(context.Background(), ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportGit failed: %v", err)
	}
	close(ch)

	var records []gitSourceRecord
	for r := range ch {
		records = append(records, r.(gitSourceRecord))
	}

	// We expect 1 record: the deletion of CVE-A.json
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	if records[0].path != "CVE-A.json" {
		t.Errorf("Expected path CVE-A.json, got %s", records[0].path)
	}
	if !records[0].isDeleted {
		t.Errorf("Expected record to be marked as deleted")
	}

	// Verify the LastSyncedCommit was updated
	if sourceRepo.Git.LastSyncedCommit != commitB.String() {
		t.Errorf("Expected LastSyncedCommit %s, got %s", commitB.String(), sourceRepo.Git.LastSyncedCommit)
	}
}
