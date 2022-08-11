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
	"time"

	"cloud.google.com/go/datastore"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"

	log "github.com/golang/glog"
)

type document struct {
	Name        string
	BaseCPE     string
	Version     string
	Commit      []byte
	When        time.Time
	RepoType    string
	FileExts    []string
	FileResults []processing.FileResult
}

func newDoc(repoInfo *preparation.Result, fileResults []processing.FileResult) document {
	return document{
		Name:        repoInfo.Name,
		BaseCPE:     repoInfo.BaseCPE,
		Version:     repoInfo.Version,
		Commit:      repoInfo.Commit[:],
		When:        repoInfo.When,
		RepoType:    repoInfo.Type,
		FileExts:    repoInfo.FileExts,
		FileResults: fileResults,
	}
}

// Store provides the functionality to check for existing documents
// in datastore and add new ones.
type Store struct {
	dsCl *datastore.Client
}

// New returns a new Store.
func New(ctx context.Context, projectID string) (*Store, error) {
	client, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &Store{dsCl: client}, nil
}

// Exists checks whether a name/hash pair already exists in datastore.
func (s *Store) Exists(ctx context.Context, name string, hash plumbing.Hash) (bool, error) {
	return false, nil
}

// Store stores a new entry in the datastore.
func (s *Store) Store(ctx context.Context, repoInfo *preparation.Result, fileResults []processing.FileResult) error {
	log.Infof("storing %s and %s", repoInfo.Name, repoInfo.Commit.String())
	key := datastore.IncompleteKey("Repo", nil)
	_, err := s.dsCl.Put(ctx, key, newDoc(repoInfo, fileResults))
	return err
}
