package datastore

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/api/iterator"
)

func (sr *SourceRepository) toModel() *models.SourceRepository {
	msr := &models.SourceRepository{
		Name:           sr.Name,
		Type:           sr.Type,
		Strictness:     sr.StrictValidation,
		IgnorePatterns: sr.IgnorePatterns,
		Extension:      sr.Extension,
		KeyPath:        sr.KeyPath,
		GitAnalysis: &models.GitAnalysisConfig{
			IgnoreGit:           sr.IgnoreGit,
			DetectCherrypicks:   sr.DetectCherrypicks,
			ConsiderAllBranches: sr.ConsiderAllBranches,
			VersionsFromRepo:    sr.VersionsFromRepo,
		},
		Link:       sr.Link,
		HumanLink:  sr.HumanLink,
		IDPrefixes: sr.DBPrefix,
	}
	switch sr.Type {
	case models.SourceRepositoryTypeGit:
		msr.Git = &models.SourceRepoGit{
			URL:              sr.RepoURL,
			Branch:           sr.RepoBranch,
			Path:             sr.DirectoryPath,
			LastSyncedCommit: sr.LastSyncedHash,
		}
	case models.SourceRepositoryTypeBucket:
		msr.Bucket = &models.SourceRepoBucket{
			Bucket:                  sr.Bucket,
			Path:                    sr.DirectoryPath,
			LastUpdated:             sr.LastUpdateDate,
			IgnoreLastImportTime:    sr.IgnoreLastImportTime,
			IgnoreDeletionThreshold: sr.IgnoreDeletionThreshold,
		}
	case models.SourceRepositoryTypeREST:
		msr.REST = &models.SourceRepoREST{
			URL:                     sr.RestApiUrl,
			LastUpdated:             sr.LastUpdateDate,
			IgnoreLastImportTime:    sr.IgnoreLastImportTime,
			IgnoreDeletionThreshold: sr.IgnoreDeletionThreshold,
		}
	}
	return msr
}

type SourceRepositoryStore struct {
	client *datastore.Client
}

func NewSourceRepositoryStore(client *datastore.Client) *SourceRepositoryStore {
	return &SourceRepositoryStore{client: client}
}

func (s *SourceRepositoryStore) Get(ctx context.Context, name string) (*models.SourceRepository, error) {
	var sr SourceRepository
	err := s.client.Get(ctx, datastore.NameKey("SourceRepository", name, nil), &sr)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get source repository: %w", err)
	}
	return sr.toModel(), nil
}

func (s *SourceRepositoryStore) Update(ctx context.Context, name string, repo *models.SourceRepository) error {
	if name != repo.Name {
		return fmt.Errorf("name mismatch: %q != %q", name, repo.Name)
	}
	sr := newSourceRepositoryFromModel(repo)
	key := datastore.NameKey("SourceRepository", name, nil)
	if _, err := s.client.Put(ctx, key, sr); err != nil {
		return fmt.Errorf("failed to put source repository: %w", err)
	}
	return nil
}

func newSourceRepositoryFromModel(r *models.SourceRepository) *SourceRepository {
	sr := &SourceRepository{
		Name:             r.Name,
		Type:             r.Type,
		StrictValidation: r.Strictness,
		IgnorePatterns:   r.IgnorePatterns,
		Extension:        r.Extension,
		KeyPath:          r.KeyPath,
		Link:             r.Link,
		HumanLink:        r.HumanLink,
		DBPrefix:         r.IDPrefixes,
	}

	if r.GitAnalysis != nil {
		sr.IgnoreGit = r.GitAnalysis.IgnoreGit
		sr.DetectCherrypicks = r.GitAnalysis.DetectCherrypicks
		sr.ConsiderAllBranches = r.GitAnalysis.ConsiderAllBranches
		sr.VersionsFromRepo = r.GitAnalysis.VersionsFromRepo
	}
	if r.Git != nil {
		sr.RepoURL = r.Git.URL
		sr.RepoBranch = r.Git.Branch
		sr.DirectoryPath = r.Git.Path
		sr.LastSyncedHash = r.Git.LastSyncedCommit
	}
	if r.Bucket != nil {
		sr.Bucket = r.Bucket.Bucket
		sr.DirectoryPath = r.Bucket.Path
		sr.LastUpdateDate = r.Bucket.LastUpdated
		sr.IgnoreLastImportTime = r.Bucket.IgnoreLastImportTime
		sr.IgnoreDeletionThreshold = r.Bucket.IgnoreDeletionThreshold
	}
	if r.REST != nil {
		sr.RestApiUrl = r.REST.URL
		sr.LastUpdateDate = r.REST.LastUpdated
		sr.IgnoreLastImportTime = r.REST.IgnoreLastImportTime
		sr.IgnoreDeletionThreshold = r.REST.IgnoreDeletionThreshold
	}
	return sr
}

func (s *SourceRepositoryStore) All(ctx context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(yield func(*models.SourceRepository, error) bool) {
		q := datastore.NewQuery("SourceRepository")
		it := s.client.Run(ctx, q)
		for {
			var sr SourceRepository
			_, err := it.Next(&sr)
			if errors.Is(err, iterator.Done) {
				return
			}
			if err != nil {
				yield(nil, fmt.Errorf("failed to get source repository: %w", err))
				return
			}
			if !yield(sr.toModel(), nil) {
				return
			}
		}
	}
}
