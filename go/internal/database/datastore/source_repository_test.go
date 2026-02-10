package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestSourceRepositoryStore_Update(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewSourceRepositoryStore(dsClient)

	testTime := time.Date(2023, 10, 26, 0, 0, 0, 0, time.UTC)
	testTime2 := time.Date(2023, 10, 27, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		repoName  string
		inputRepo *models.SourceRepository
		want      *SourceRepository
		wantErr   bool
	}{
		{
			name:     "Update Git Repository",
			repoName: "test-git-repo",
			inputRepo: &models.SourceRepository{
				Name:           "test-git-repo",
				Type:           models.SourceRepositoryTypeGit,
				Strictness:     true,
				IgnorePatterns: []string{"abc"},
				Extension:      ".json",
				KeyPath:        "key",
				Link:           "http://link.com",
				HumanLink:      "http://human.link.com",
				IDPrefixes:     []string{"TEST"},
				Git: &models.SourceRepoGit{
					URL:              "http://git.url",
					Branch:           "main",
					Path:             "test/path",
					LastSyncedCommit: "commit-hash",
				},
				GitAnalysis: &models.GitAnalysisConfig{
					IgnoreGit:           true,
					DetectCherrypicks:   true,
					ConsiderAllBranches: true,
					VersionsFromRepo:    true,
				},
			},
			want: &SourceRepository{
				Name:                "test-git-repo",
				Type:                models.SourceRepositoryTypeGit,
				StrictValidation:    true,
				IgnorePatterns:      []string{"abc"},
				Extension:           ".json",
				KeyPath:             "key",
				Link:                "http://link.com",
				HumanLink:           "http://human.link.com",
				DBPrefix:            []string{"TEST"},
				RepoURL:             "http://git.url",
				RepoBranch:          "main",
				DirectoryPath:       "test/path",
				LastSyncedHash:      "commit-hash",
				IgnoreGit:           true,
				DetectCherrypicks:   true,
				ConsiderAllBranches: true,
				VersionsFromRepo:    true,
			},
		},
		{
			name:     "Update Bucket Repository",
			repoName: "test-bucket-repo",
			inputRepo: &models.SourceRepository{
				Name: "test-bucket-repo",
				Type: models.SourceRepositoryTypeBucket,
				Bucket: &models.SourceRepoBucket{
					Name:                    "test-bucket",
					Path:                    "test/path",
					LastUpdated:             &testTime,
					IgnoreLastImportTime:    true,
					IgnoreDeletionThreshold: true,
				},
			},
			want: &SourceRepository{
				Name:                    "test-bucket-repo",
				Type:                    models.SourceRepositoryTypeBucket,
				Bucket:                  "test-bucket",
				DirectoryPath:           "test/path",
				LastUpdateDate:          &testTime,
				IgnoreLastImportTime:    true,
				IgnoreDeletionThreshold: true,
			},
		},
		{
			name:     "Update REST Repository",
			repoName: "test-rest-repo",
			inputRepo: &models.SourceRepository{
				Name: "test-rest-repo",
				Type: models.SourceRepositoryTypeREST,
				REST: &models.SourceRepoREST{
					URL:                     "http://rest.url",
					LastUpdated:             &testTime2,
					IgnoreLastImportTime:    true,
					IgnoreDeletionThreshold: true,
				},
			},
			want: &SourceRepository{
				Name:                    "test-rest-repo",
				Type:                    models.SourceRepositoryTypeREST,
				RESTAPIURL:              "http://rest.url",
				LastUpdateDate:          &testTime2,
				IgnoreLastImportTime:    true,
				IgnoreDeletionThreshold: true,
			},
		},
		{
			name:     "Name Mismatch",
			repoName: "wrong-name",
			inputRepo: &models.SourceRepository{
				Name: "correct-name",
				Type: models.SourceRepositoryTypeGit,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Update(ctx, tt.repoName, tt.inputRepo)
			if (err != nil) != tt.wantErr {
				t.Errorf("Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var got SourceRepository
			key := datastore.NameKey("SourceRepository", tt.repoName, nil)
			if err := dsClient.Get(ctx, key, &got); err != nil {
				t.Fatalf("Failed to get entity from datastore: %v", err)
			}

			if diff := cmp.Diff(tt.want, &got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Datastore entity mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSourceRepositoryStore_Get(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewSourceRepositoryStore(dsClient)

	testTime := time.Date(2023, 10, 26, 0, 0, 0, 0, time.UTC)

	// Prepare data
	repo := &models.SourceRepository{
		Name:           "test-repo",
		Type:           models.SourceRepositoryTypeGit,
		Strictness:     true,
		IgnorePatterns: []string{"abc"},
		Extension:      ".json",
		KeyPath:        "key",
		Link:           "http://link.com",
		HumanLink:      "http://human.link.com",
		IDPrefixes:     []string{"TEST"},
		Git: &models.SourceRepoGit{
			URL:              "http://git.url",
			Branch:           "main",
			Path:             "test/path",
			LastSyncedCommit: "commit-hash",
		},
		GitAnalysis: &models.GitAnalysisConfig{
			IgnoreGit:           true,
			DetectCherrypicks:   true,
			ConsiderAllBranches: true,
			VersionsFromRepo:    true,
		},
	}

	// Helper to create entity in Datastore directly or via Update (we use Update since we tested it)
	if err := store.Update(ctx, repo.Name, repo); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name    string
		getRepo string
		want    *models.SourceRepository
		wantErr bool
	}{
		{
			name:    "Get Existing Repository",
			getRepo: "test-repo",
			want:    repo,
		},
		{
			name:    "Get Non-Existent Repository",
			getRepo: "non-existent",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.Get(ctx, tt.getRepo)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !errors.Is(err, models.ErrNotFound) {
					t.Errorf("Get() error = %v, want models.ErrNotFound", err)
				}

				return
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Get() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Test Bucket Repo toDomain conversion specifically for pointer handling
	bucketRepo := &models.SourceRepository{
		Name: "test-bucket-repo",
		Type: models.SourceRepositoryTypeBucket,
		Bucket: &models.SourceRepoBucket{
			Name:        "test-bucket",
			LastUpdated: &testTime,
		},
		GitAnalysis: &models.GitAnalysisConfig{},
	}
	if err := store.Update(ctx, bucketRepo.Name, bucketRepo); err != nil {
		t.Fatalf("Failed to setup bucket test data: %v", err)
	}

	gotBucket, err := store.Get(ctx, "test-bucket-repo")
	if err != nil {
		t.Fatalf("Failed to get bucket repo: %v", err)
	}
	if diff := cmp.Diff(bucketRepo, gotBucket, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Get() Bucket repo mismatch (-want +got):\n%s", diff)
	}
}

func TestSourceRepositoryStore_All(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewSourceRepositoryStore(dsClient)

	repos := []*models.SourceRepository{
		{
			Name: "repo-1",
			Type: models.SourceRepositoryTypeGit,
			Git: &models.SourceRepoGit{
				URL: "http://git.url/1",
			},
			GitAnalysis: &models.GitAnalysisConfig{},
		},
		{
			Name: "repo-2",
			Type: models.SourceRepositoryTypeBucket,
			Bucket: &models.SourceRepoBucket{
				Name: "bucket-2",
			},
			GitAnalysis: &models.GitAnalysisConfig{},
		},
	}

	for _, r := range repos {
		if err := store.Update(ctx, r.Name, r); err != nil {
			t.Fatalf("Failed to setup test data: %v", err)
		}
	}

	got := make([]*models.SourceRepository, 0, len(repos))
	for r, err := range store.All(ctx) {
		if err != nil {
			t.Fatalf("All() iterator error: %v", err)
		}
		got = append(got, r)
	}

	sortOpt := cmpopts.SortSlices(func(a, b *models.SourceRepository) bool {
		return a.Name < b.Name
	})

	if diff := cmp.Diff(repos, got, cmpopts.EquateEmpty(), sortOpt); diff != "" {
		t.Errorf("All() mismatch (-want +got):\n%s", diff)
	}
}
