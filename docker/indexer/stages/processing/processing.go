// Package processing implements the hashing step for each provide input.
package processing

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv.dev/docker/indexer/shared"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"

	log "github.com/golang/glog"
	pb "github.com/google/osv.dev/docker/indexer/proto"
)

const workers = 25

// Storer is used to permanently store the results.
type Storer interface {
	Store(ctx context.Context, repoInfo *preparation.Result, fileResults []FileResult) error
}

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string
	Hash [md5.Size]byte
}

// Stage holds the data structures necessary to perform the processing.
type Stage struct {
	Storer  Storer
	RepoHdl *storage.BucketHandle
}

// Run runs the stages and hashes all files for each incoming request.
func (s *Stage) Run(ctx context.Context, input chan *preparation.Result) error {
	wErr := make(chan error, workers)
	routineCtr := 0
	wg := sync.WaitGroup{}
	for {
		if routineCtr >= workers {
			wg.Wait()
			routineCtr = 0
		}
		var (
			repoInfo *preparation.Result
			ok       bool
		)
		select {
		case repoInfo, ok = <-input:
		case err := <-wErr:
			log.Errorf("worker returned an error: %v", err)
		case <-ctx.Done():
			return context.Canceled
		}
		if !ok {
			break
		}

		routineCtr++
		wg.Add(1)
		go func() {
			defer wg.Done()

			var err error
			switch repoInfo.Type {
			case pb.RepositoryType_GIT:
				err = s.processGit(ctx, repoInfo)
			default:
				err = errors.New("unknown repository type")
			}
			if err != nil {
				wErr <- err
			}
		}()
	}
	wg.Wait()
	return nil
}

func (s *Stage) processGit(ctx context.Context, repoInfo *preparation.Result) error {
	repoDir, err := shared.CopyFromBucket(ctx, s.RepoHdl, repoInfo.Name)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(repoDir); err != nil {
			log.Errorf("failed to remove repo folder: %v", err)
		}
	}()
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("failed to open repo: %v", err)
	}
	tree, err := repo.Worktree()
	if err != nil {
		return err
	}
	if err := tree.Checkout(repoInfo.CheckoutOptions); err != nil {
		return err
	}

	var fileResults []FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		for _, ext := range repoInfo.FileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				fileResults = append(fileResults, FileResult{
					Path: p,
					Hash: md5.Sum(buf),
				})
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.Storer.Store(ctx, repoInfo, fileResults)
}
