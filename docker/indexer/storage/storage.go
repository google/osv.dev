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
