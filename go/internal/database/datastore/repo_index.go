// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datastore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"golang.org/x/sync/errgroup"
)

const (
	// RepoIndexKind matches the Datastore kind for repository indexes.
	RepoIndexKind = "RepoIndex"

	// RepoIndexBucketKind matches the Datastore kind for repository index buckets.
	RepoIndexBucketKind = "RepoIndexBucket"

	// MaxConcurrentQueries limits the number of parallel Datastore queries we run.
	MaxConcurrentQueries = 32
)

// RepoIndexStore implements models.RepoIndexStore using Google Cloud Datastore.
type RepoIndexStore struct {
	client *datastore.Client
}

var _ models.RepoIndexStore = (*RepoIndexStore)(nil)

// NewRepoIndexStore creates a new RepoIndexStore.
func NewRepoIndexStore(client *datastore.Client) *RepoIndexStore {
	return &RepoIndexStore{client: client}
}

// QueryBuckets finds all RepoIndexBucket entities matching any of the given node hashes,
// grouped by the hex-encoded string of the node hash.
func (s *RepoIndexStore) QueryBuckets(ctx context.Context, nodeHashes [][]byte) (map[string][]*models.RepoIndexBucket, error) {
	var mu sync.Mutex
	results := make(map[string][]*models.RepoIndexBucket)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrentQueries)

	for _, hash := range nodeHashes {
		h := hash // capture loop variable
		g.Go(func() error {
			q := datastore.NewQuery(RepoIndexBucketKind).
				FilterField("node_hash", "=", h).
				Limit(models.MaxMatchesToCare)

			var dbBuckets []*RepoIndexBucket
			keys, err := s.client.GetAll(ctx, q, &dbBuckets)
			if err != nil {
				return fmt.Errorf("failed to fetch RepoIndexBucket for hash %x: %w", h, err)
			}

			var matched []*models.RepoIndexBucket
			for i, k := range keys {
				parentKey := k.Parent
				var parentID string
				if parentKey != nil {
					parentID = parentKey.Name
				}

				matched = append(matched, &models.RepoIndexBucket{
					ParentID:       parentID,
					NodeHash:       dbBuckets[i].NodeHash,
					FilesContained: dbBuckets[i].FilesContained,
				})
			}

			hexHash := hex.EncodeToString(h)
			mu.Lock()
			results[hexHash] = matched
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// GetRepoIndexes fetches the parent RepoIndex entities for the given IDs.
func (s *RepoIndexStore) GetRepoIndexes(ctx context.Context, ids []string) ([]*models.RepoIndex, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	keys := make([]*datastore.Key, len(ids))
	for i, id := range ids {
		keys[i] = datastore.NameKey(RepoIndexKind, id, nil)
	}

	dbIndexes := make([]*RepoIndex, len(ids))
	err := s.client.GetMulti(ctx, keys, dbIndexes)
	if err != nil {
		// If some entities are not found, GetMulti returns datastore.ErrMultiErr
		var multiErr datastore.MultiError
		if !errors.As(err, &multiErr) {
			return nil, fmt.Errorf("failed to batch get RepoIndexes: %w", err)
		}
	}

	results := make([]*models.RepoIndex, 0, len(dbIndexes))
	for i, dbIdx := range dbIndexes {
		if dbIdx == nil {
			continue
		}
		results = append(results, &models.RepoIndex{
			ID:                ids[i],
			Name:              dbIdx.Name,
			BaseCPE:           dbIdx.BaseCPE,
			Commit:            dbIdx.Commit,
			Tag:               dbIdx.Tag,
			When:              dbIdx.When,
			RepoType:          dbIdx.RepoType,
			RepoAddr:          dbIdx.RepoAddr,
			FileExts:          dbIdx.FileExts,
			FileHashType:      dbIdx.FileHashType,
			EmptyBucketBitmap: dbIdx.EmptyBucketBitmap,
			FileCount:         dbIdx.FileCount,
		})
	}

	return results, nil
}
