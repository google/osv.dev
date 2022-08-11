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

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"

	log "github.com/golang/glog"
)

type Store struct {
}

func (s *Store) Exists(ctx context.Context, name string, hash plumbing.Hash) (bool, error) {
	return false, nil
}

func (s *Store) Store(ctx context.Context, repoInfo *preparation.Result, fileResults []processing.FileResult) error {
	log.Infof("storing %s and %s", repoInfo.Name, repoInfo.Commit.String())
	return nil
}
