package importer

import (
	"context"
	"errors"
	"io"
	"testing"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
)

// Just some randomly SHA1 strings as commit hash
const (
	commitA = "aba9cc47a746783b86f16425e27afb1c044d47df"
	commitB = "3eff134ce2a70d0af05040691ffb4c9cb763c980"
)

func TestGitSourceRecord_Open(t *testing.T) {
	mockClient := &mockGitterClient{
		fileContentFunc: func(_ context.Context, _ *pb.FileContentRequest) (*pb.FileContentResponse, error) {
			return &pb.FileContentResponse{
				Content: []byte("data"),
			}, nil
		},
	}

	record := gitSourceRecord{
		client:  mockClient,
		repoURL: "https://github.com/mock/test-repo.git",
		commit:  commitA,
		path:    "test.go",
	}

	reader, err := record.Open(t.Context())
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

func TestGitSourceRecord_Open_Error(t *testing.T) {
	mockClient := &mockGitterClient{
		fileContentFunc: func(_ context.Context, _ *pb.FileContentRequest) (*pb.FileContentResponse, error) {
			return nil, errors.New("gitter fetch content error")
		},
	}

	record := gitSourceRecord{
		client:  mockClient,
		repoURL: "https://github.com/mock/test-repo.git",
		commit:  commitA,
		path:    "test.go",
	}

	_, err := record.Open(t.Context())
	if err == nil {
		t.Fatalf("Expected error from Open, got nil")
	}
}

func TestHandleImportGit(t *testing.T) {
	mockClient := &mockGitterClient{
		fileDiffsFunc: func(_ context.Context, _ *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
			return &pb.FileDiffsResponse{
				LatestCommit: commitB,
				Changes: []*pb.FileChange{
					{FromPath: "ignore-1.json", ToPath: "ignore-1.json"}, // should be ignored
					{FromPath: "CVE-A.json", ToPath: "CVE-A.json"},       // modified
					{FromPath: "", ToPath: "CVE-B.json"},                 // added
				},
			}, nil
		},
	}

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]any),
	}

	config := Config{
		SourceRepoStore: mockStore,
		GitterClient:    mockClient,
	}

	sourceRepo := &models.SourceRepository{
		Name:           "test-git-repo",
		Type:           models.SourceRepositoryTypeGit,
		Extension:      ".json",
		IgnorePatterns: []string{"ignore.*"},
		Git: &models.SourceRepoGit{
			URL:              "https://github.com/mock/test-repo.git",
			LastSyncedCommit: commitA,
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleImportGit(t.Context(), ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportGit failed: %v", err)
	}
	close(ch)

	items := make([]WorkItem, 0, 10)
	for r := range ch {
		items = append(items, r)
	}

	if len(items) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(items))
	}

	paths := make(map[string]bool)
	for _, it := range items {
		paths[it.SourcePath] = true
	}

	if !paths["CVE-A.json"] {
		t.Errorf("Expected CVE-A.json to be processed")
	}
	if !paths["CVE-B.json"] {
		t.Errorf("Expected CVE-B.json to be processed")
	}

	if sourceRepo.Git.LastSyncedCommit != commitB {
		t.Errorf("Expected LastSyncedCommit %s, got %s", commitB, sourceRepo.Git.LastSyncedCommit)
	}
}

func TestHandleImportGit_Deletion(t *testing.T) {
	mockClient := &mockGitterClient{
		fileDiffsFunc: func(_ context.Context, _ *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
			return &pb.FileDiffsResponse{
				LatestCommit: commitB,
				Changes: []*pb.FileChange{
					{FromPath: "CVE-A.json", ToPath: ""}, // deleted
				},
			}, nil
		},
	}

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]any),
	}

	config := Config{
		SourceRepoStore: mockStore,
		GitterClient:    mockClient,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-git-repo",
		Type:      models.SourceRepositoryTypeGit,
		Extension: ".json",
		Git: &models.SourceRepoGit{
			URL:              "https://github.com/mock/test-repo.git",
			LastSyncedCommit: commitA,
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleImportGit(t.Context(), ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleImportGit failed: %v", err)
	}
	close(ch)

	items := make([]WorkItem, 0, 10)
	for r := range ch {
		items = append(items, r)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(items))
	}

	if items[0].SourcePath != "CVE-A.json" {
		t.Errorf("Expected path CVE-A.json, got %s", items[0].SourcePath)
	}
	if items[0].Action != ActionWithdraw {
		t.Errorf("Expected record to be marked as Action=Withdraw")
	}

	if sourceRepo.Git.LastSyncedCommit != commitB {
		t.Errorf("Expected LastSyncedCommit %s, got %s", commitB, sourceRepo.Git.LastSyncedCommit)
	}
}

func TestHandleImportGit_GitterError(t *testing.T) {
	mockClient := &mockGitterClient{
		fileDiffsFunc: func(_ context.Context, _ *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
			return nil, errors.New("gitter diff error")
		},
	}

	config := Config{
		SourceRepoStore: &mockSourceRepositoryStore{},
		GitterClient:    mockClient,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-git-repo",
		Type:      models.SourceRepositoryTypeGit,
		Extension: ".json",
		Git: &models.SourceRepoGit{
			URL: "https://github.com/mock/test-repo.git",
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleImportGit(t.Context(), ch, config, sourceRepo)
	if err == nil {
		t.Fatalf("Expected error from handleImportGit, got nil")
	}
}

func TestHandleReconcileGit(t *testing.T) {
	mockClient := &mockGitterClient{
		fileDiffsFunc: func(_ context.Context, _ *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
			return &pb.FileDiffsResponse{
				LatestCommit: commitB,
				Changes: []*pb.FileChange{
					{FromPath: "", ToPath: "CVE-A.json"},
					{FromPath: "", ToPath: "tracked_dir/CVE-B.json"},
					{FromPath: "", ToPath: "ignored.txt"},
				},
			}, nil
		},
	}

	mockStore := &mockSourceRepositoryStore{
		updates: make(map[string]any),
	}
	mockVulnStore := &mockVulnerabilityStore{
		Entries: make(map[string][]*models.VulnSourceRef),
	}

	config := Config{
		SourceRepoStore:    mockStore,
		VulnerabilityStore: mockVulnStore,
		GitterClient:       mockClient,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-git-repo",
		Type:      models.SourceRepositoryTypeGit,
		Extension: ".json",
		Git: &models.SourceRepoGit{
			URL: "https://github.com/mock/test-repo.git",
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleReconcileGit(t.Context(), ch, config, sourceRepo)
	if err != nil {
		t.Fatalf("handleReconcileGit failed: %v", err)
	}
	close(ch)

	items := make([]WorkItem, 0, 10)
	for r := range ch {
		items = append(items, r)
	}

	if len(items) != 2 {
		t.Fatalf("Expected 2 records to be reconciled, got %d", len(items))
	}

	paths := make(map[string]bool)
	for _, it := range items {
		paths[it.SourcePath] = true
	}

	if !paths["CVE-A.json"] {
		t.Errorf("Expected CVE-A.json to be reconciled")
	}
	if !paths["tracked_dir/CVE-B.json"] {
		t.Errorf("Expected tracked_dir/CVE-B.json to be reconciled")
	}
}

func TestHandleReconcileGit_GitterError(t *testing.T) {
	mockClient := &mockGitterClient{
		fileDiffsFunc: func(_ context.Context, _ *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
			return nil, errors.New("gitter reconcile error")
		},
	}

	config := Config{
		SourceRepoStore:    &mockSourceRepositoryStore{},
		VulnerabilityStore: &mockVulnerabilityStore{},
		GitterClient:       mockClient,
	}

	sourceRepo := &models.SourceRepository{
		Name:      "test-git-repo",
		Type:      models.SourceRepositoryTypeGit,
		Extension: ".json",
		Git: &models.SourceRepoGit{
			URL: "https://github.com/mock/test-repo.git",
		},
	}

	ch := make(chan WorkItem, 10)
	err := handleReconcileGit(t.Context(), ch, config, sourceRepo)
	if err == nil {
		t.Fatalf("Expected error from handleReconcileGit, got nil")
	}
}
