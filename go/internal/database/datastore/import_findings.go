package datastore

import (
	"context"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

type ImportFindingsStore struct {
	client *datastore.Client
}

var _ models.ImportFindingsStore = (*ImportFindingsStore)(nil)

func NewImportFindingsStore(client *datastore.Client) *ImportFindingsStore {
	return &ImportFindingsStore{client: client}
}

func (s *ImportFindingsStore) Clear(ctx context.Context, id string) error {
	key := datastore.NameKey("ImportFinding", id, nil)
	return s.client.Delete(ctx, key)
}
