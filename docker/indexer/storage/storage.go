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
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"
)

const (
	kind   = "RepoIndex"
	keyFmt = "%s-%s-%x"
)

// document represents a single repository entry in datastore.
type document struct {
	Name         string                  `datastore:"name"`
	BaseCPE      string                  `datastore:"base_cpe"`
	Version      string                  `datastore:"version"`
	Commit       []byte                  `datastore:"commit"`
	When         time.Time               `datastore:"when"`
	RepoType     string                  `datastore:"repo_type"`
	RepoAddr     string                  `datastore:"repo_addr"`
	FileExts     []string                `datastore:"file_exts"`
	FileHashType string                  `datastore:"file_hash_type"`
	FileResults  []processing.FileResult `datastore:"file_results"`
}

func newDoc(repoInfo *preparation.Result, hashType string, fileResults []processing.FileResult) *document {
	return &document{
		Name:         repoInfo.Name,
		BaseCPE:      repoInfo.BaseCPE,
		Version:      repoInfo.Version,
		Commit:       repoInfo.Commit[:],
		When:         repoInfo.When,
		RepoType:     repoInfo.Type,
		RepoAddr:     repoInfo.Addr,
		FileExts:     repoInfo.FileExts,
		FileHashType: hashType,
		FileResults:  fileResults,
	}
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
	if _, ok := s.cache.Load(fmt.Sprintf(keyFmt, addr, hashType, hash)); ok {
		return true, nil
	}
	key := datastore.NameKey(kind, fmt.Sprintf(keyFmt, addr, hashType, hash), nil)
	tmp := &document{}
	if err := s.dsCl.Get(ctx, key, tmp); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return false, nil
		}
		return false, err
	}
	s.cache.Store(fmt.Sprintf(keyFmt, addr, hashType, hash), true)
	return true, nil
}

// Store stores a new entry in datastore.
func (s *Store) Store(ctx context.Context, repoInfo *preparation.Result, hashType string, fileResults []processing.FileResult) error {
	key := datastore.NameKey(kind, fmt.Sprintf(keyFmt, repoInfo.Addr, hashType, repoInfo.Commit[:]), nil)
	_, err := s.dsCl.Put(ctx, key, newDoc(repoInfo, hashType, fileResults))
	return err
}

// Close closes the datastore client.
func (s *Store) Close() {
	s.dsCl.Close()
}
