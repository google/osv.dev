/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Package storage provides functionality to interact with permanent storage.
package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv.dev/docker/indexer/shared"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"
)

const (
	docKind    = "RepoIndex"
	bucketKind = "RepoIndexBucket"
	// Address-HashType-ReferenceHash
	docKeyFmt = "%s-%s-%x"
	// BucketHash-HashType-NumberOfFiles
	bucketKeyFmt            = "%x-%s-%d"
	datastoreMultiEntrySize = 490
)

// document represents a single repository entry in datastore.
type document struct {
	Name              string    `datastore:"name"`
	BaseCPE           string    `datastore:"base_cpe"`
	Commit            []byte    `datastore:"commit"`
	Tag               string    `datastore:"tag"`
	Version           string    `datastore:"version,omitempty"` // Deprecated: version is no longer used in favour of tags
	When              time.Time `datastore:"when,omitempty"`
	RepoType          string    `datastore:"repo_type"`
	RepoAddr          string    `datastore:"repo_addr"`
	FileExts          []string  `datastore:"file_exts"`
	FileHashType      string    `datastore:"file_hash_type"`
	EmptyBucketBitmap []byte    `datastore:"empty_bucket_bitmap"`
	FileCount         int       `datastore:"file_count"`
	DocumentVersion   int       `datastore:"document_version"`
}

func newDoc(repoInfo *preparation.Result, hashType string) *document {
	doc := &document{
		Name:              repoInfo.Name,
		BaseCPE:           repoInfo.BaseCPE,
		Commit:            repoInfo.Commit[:],
		Tag:               repoInfo.CommitTag,
		When:              repoInfo.When,
		RepoType:          repoInfo.Type,
		RepoAddr:          repoInfo.Addr,
		FileExts:          repoInfo.FileExts,
		FileHashType:      hashType,
		EmptyBucketBitmap: repoInfo.EmptyBucketBitmap,
		FileCount:         repoInfo.FileCount,
		DocumentVersion:   shared.LatestDocumentVersion,
	}
	return doc
}

// Store provides the functionality to check for existing documents
// in datastore and add new ones.
type Store struct {
	dsCl  *datastore.Client
	cache sync.Map
}

// New returns a new Store.
func New(ctx context.Context, projectID string) (*Store, error) {
	client, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &Store{dsCl: client, cache: sync.Map{}}, nil
}

// Exists checks whether a name/hash pair already exists in datastore.
func (s *Store) Exists(ctx context.Context, addr string, hashType string, hash plumbing.Hash) (bool, error) {
	if _, ok := s.cache.Load(fmt.Sprintf(docKeyFmt, addr, hashType, hash[:])); ok {
		// The cache is per instance, so if it has loaded it before, it always has the latest version
		return true, nil
	}
	// hash[:], the [:] is important, since the formatting uses %x, which will return a different result if not used
	// This is because plumbing.Hash implements it's own String() method, and the %x will create a hex of the hex produced
	// by plumbing.Hash String()
	key := datastore.NameKey(docKind, fmt.Sprintf(docKeyFmt, addr, hashType, hash[:]), nil)
	tmp := &document{}
	if err := s.dsCl.Get(ctx, key, tmp); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return false, nil
		}
		return false, err
	}
	s.cache.Store(fmt.Sprintf(docKeyFmt, addr, hashType, hash[:]), true)
	return tmp.DocumentVersion == shared.LatestDocumentVersion, nil
}

// Store stores a new entry in datastore.
func (s *Store) Store(ctx context.Context, repoInfo *preparation.Result, hashType string, treeNodes []*processing.BucketNode) error {
	docKey := datastore.NameKey(docKind, fmt.Sprintf(docKeyFmt, repoInfo.Addr, hashType, repoInfo.Reference[:]), nil)

	// There are slightly too many items to put in a transaction (max 500 entries per transaction)
	putMultiKeys := []*datastore.Key{}
	putMultiNodes := []*processing.BucketNode{}
	for _, node := range treeNodes {
		if node.FilesContained == 0 {
			continue
		}

		bucketKey := datastore.NameKey(
			bucketKind,
			fmt.Sprintf(bucketKeyFmt, node.NodeHash, hashType, node.FilesContained),
			docKey,
		)

		putMultiKeys = append(putMultiKeys, bucketKey)
		putMultiNodes = append(putMultiNodes, node)
	}

	// Batch Puts into datastoreMultiEntrySize chunks
	for i := 0; i < len(putMultiKeys); i += datastoreMultiEntrySize {
		end := i + datastoreMultiEntrySize
		if end > len(putMultiKeys) {
			end = len(putMultiKeys)
		}

		_, err := s.dsCl.PutMulti(ctx, putMultiKeys[i:end], putMultiNodes[i:end])
		if err != nil {
			return err
		}
	}

	// Leave the repoIndex entry to last so that if previous input fails
	// the controller will try again
	doc := newDoc(repoInfo, hashType)
	_, err := s.dsCl.Put(ctx, docKey, doc)
	if err != nil {
		return err
	}

	return nil
}

// Cleans old buckets from the datastore
func (s *Store) Clean(ctx context.Context, repoInfo *preparation.Result, hashType string) error {
	docKey := datastore.NameKey(docKind, fmt.Sprintf(docKeyFmt, repoInfo.Addr, hashType, repoInfo.Reference[:]), nil)

	query := datastore.NewQuery(bucketKind).Ancestor(docKey)

	bucketHashes := []*processing.BucketNode{}
	// GetAll should never return more than 2x the max number of buckets (512*2 = 1024) results.
	bucketKeys, err := s.dsCl.GetAll(ctx, query, &bucketHashes)

	if err != nil {
		return err
	}

	keysToDelete := []*datastore.Key{}
	for i, key := range bucketKeys {
		if bucketHashes[i].DocumentVersion != shared.LatestDocumentVersion {
			keysToDelete = append(keysToDelete, key)
		}
	}
	err = s.dsCl.DeleteMulti(ctx, keysToDelete)

	return err
}

// Close closes the datastore client.
func (s *Store) Close() {
	s.dsCl.Close()
}
