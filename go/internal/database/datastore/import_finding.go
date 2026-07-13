package datastore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/api/iterator"
)

type ImportFinding struct {
	Key         *datastore.Key          `datastore:"__key__"`
	BugID       string                  `datastore:"bug_id"`
	Source      string                  `datastore:"source"`
	Findings    []models.ImportFindings `datastore:"findings"`
	FirstSeen   time.Time               `datastore:"first_seen"`
	LastAttempt time.Time               `datastore:"last_attempt"`
}

type ImportFindingsStore struct {
	dsClient      *datastore.Client
	storageClient *storage.Client
	bucketName    string
	prefix        string
}

var _ models.ImportFindingsStore = (*ImportFindingsStore)(nil)

func NewImportFindingsStore(dsClient *datastore.Client, storageClient *storage.Client, bucketName, prefix string) *ImportFindingsStore {
	return &ImportFindingsStore{
		dsClient:      dsClient,
		storageClient: storageClient,
		bucketName:    bucketName,
		prefix:        prefix,
	}
}

func (s *ImportFindingsStore) Clear(ctx context.Context, id string) error {
	key := datastore.NameKey("ImportFinding", id, nil)
	return s.dsClient.Delete(ctx, key)
}

func (s *ImportFindingsStore) ListIDs(ctx context.Context) ([]string, error) {
	query := datastore.NewQuery("ImportFinding").KeysOnly()
	keys, err := s.dsClient.GetAll(ctx, query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing findings: %w", err)
	}
	ids := make([]string, len(keys))
	for i, key := range keys {
		ids[i] = key.Name
	}

	return ids, nil
}

func (s *ImportFindingsStore) GetMulti(ctx context.Context, bugIDs []string) ([]*models.ImportFinding, error) {
	keys := make([]*datastore.Key, len(bugIDs))
	for i, id := range bugIDs {
		keys[i] = datastore.NameKey("ImportFinding", id, nil)
	}

	entities := make([]*ImportFinding, len(bugIDs))
	err := s.dsClient.GetMulti(ctx, keys, entities)
	if err != nil {
		var multiErr datastore.MultiError
		if errors.As(err, &multiErr) {
			for i, e := range multiErr {
				if errors.Is(e, datastore.ErrNoSuchEntity) {
					entities[i] = nil
				} else if e != nil {
					return nil, fmt.Errorf("failed to get multi: %w", err)
				}
			}
		} else {
			return nil, fmt.Errorf("failed to get multi: %w", err)
		}
	}

	findings := make([]*models.ImportFinding, len(bugIDs))
	for i, entity := range entities {
		if entity != nil {
			findings[i] = entity.toModel()
		}
	}

	return findings, nil
}

func (s *ImportFindingsStore) PutMulti(ctx context.Context, findings []*models.ImportFinding) error {
	keys := make([]*datastore.Key, len(findings))
	entities := make([]*ImportFinding, len(findings))
	for i, f := range findings {
		keys[i] = datastore.NameKey("ImportFinding", f.BugID, nil)
		entities[i] = newImportFindingFromModel(f)
	}

	if _, err := s.dsClient.PutMulti(ctx, keys, entities); err != nil {
		return fmt.Errorf("failed to put multi: %w", err)
	}

	return nil
}

func (s *ImportFindingsStore) DeleteMulti(ctx context.Context, bugIDs []string) error {
	keys := make([]*datastore.Key, len(bugIDs))
	for i, id := range bugIDs {
		keys[i] = datastore.NameKey("ImportFinding", id, nil)
	}

	if err := s.dsClient.DeleteMulti(ctx, keys); err != nil {
		return fmt.Errorf("failed to delete multi: %w", err)
	}

	return nil
}

func (s *ImportFindingsStore) UploadResult(ctx context.Context, source string, data []byte) error {
	bucket := s.storageClient.Bucket(s.bucketName)
	targetPath := filepath.Join(s.prefix, source, "result.json")
	w := bucket.Object(targetPath).NewWriter(ctx)
	w.ContentType = "application/json"
	if _, err := w.Write(data); err != nil {
		w.Close()
		return fmt.Errorf("failed to write object to GCS: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer: %w", err)
	}

	return nil
}

func (s *ImportFindingsStore) ListResultSources(ctx context.Context) ([]string, error) {
	bucket := s.storageClient.Bucket(s.bucketName)
	var objects []string
	it := bucket.Objects(ctx, &storage.Query{Prefix: s.prefix})
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in GCS: %w", err)
		}
		objects = append(objects, attrs.Name)
	}

	return objects, nil
}

func (s *ImportFindingsStore) DeleteResult(ctx context.Context, path string) error {
	bucket := s.storageClient.Bucket(s.bucketName)
	if err := bucket.Object(path).Delete(ctx); err != nil {
		return fmt.Errorf("failed to delete object in GCS: %w", err)
	}

	return nil
}

func (s *ImportFindingsStore) ListAllFromSource(ctx context.Context, source string) ([]*models.ImportFinding, error) {
	query := datastore.NewQuery("ImportFinding").FilterField("source", "=", source)
	var entities []*ImportFinding
	if _, err := s.dsClient.GetAll(ctx, query, &entities); err != nil {
		return nil, fmt.Errorf("failed to fetch import findings: %w", err)
	}
	findings := make([]*models.ImportFinding, len(entities))
	for i, entity := range entities {
		findings[i] = entity.toModel()
	}

	return findings, nil
}

func (f *ImportFinding) toModel() *models.ImportFinding {
	return &models.ImportFinding{
		BugID:       f.BugID,
		Source:      f.Source,
		Findings:    f.Findings,
		FirstSeen:   f.FirstSeen,
		LastAttempt: f.LastAttempt,
	}
}

func newImportFindingFromModel(f *models.ImportFinding) *ImportFinding {
	return &ImportFinding{
		BugID:       f.BugID,
		Source:      f.Source,
		Findings:    f.Findings,
		FirstSeen:   f.FirstSeen,
		LastAttempt: f.LastAttempt,
	}
}
