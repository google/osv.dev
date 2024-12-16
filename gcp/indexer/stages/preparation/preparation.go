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
// Package preparation provides functionality to extract tags, branches and commits from repository configurations.
package preparation

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/osv.dev/gcp/indexer/config"
	"github.com/google/osv.dev/gcp/indexer/shared"
	"golang.org/x/sync/semaphore"

	log "github.com/golang/glog"
)

const workers = 5

// Result is the data structure returned by the stage.
type Result struct {
	Name              string
	BaseCPE           string
	CheckoutOptions   *git.CheckoutOptions
	Commit            plumbing.Hash
	Reference         plumbing.Hash
	CommitTag         string
	When              time.Time
	Type              string
	Addr              string
	FileExts          []string
	EmptyBucketBitmap []byte
	FileCount         int
}

// Checker interface is used to check whether a name/hash pair already exists in storage.
type Checker interface {
	Exists(ctx context.Context, addr string, hashType string, hash plumbing.Hash) (bool, error)
}

// Stage holds the data types necessary to process repository configuration.
type Stage struct {
	Checker Checker
	RepoHdl *storage.BucketHandle
	Output  *pubsub.Topic
}

// Run runs the stage and outputs Result data types to the results channel.
func (s *Stage) Run(ctx context.Context, cfgs []*config.RepoConfig) error {
	wCtx, wCancel := context.WithCancel(ctx)
	defer wCancel()

	sem := semaphore.NewWeighted(workers)
	for _, repoCfg := range cfgs {
		if err := sem.Acquire(wCtx, 1); err != nil {
			return fmt.Errorf("failed to acquire semaphore: %v", err)
		}

		go func(ctx context.Context, repoCfg *config.RepoConfig) {
			defer sem.Release(1)

			var err error
			select {
			case <-ctx.Done():
				log.Error(context.Canceled)
				return
			default:
			}
			log.Infof("received config for %s", repoCfg.Name)
			switch repoCfg.Type {
			case shared.Git:
				err = s.processGit(ctx, repoCfg)
			default:
				log.Errorf("unsupported config type: %s", repoCfg.Type)
			}
			if err != nil {
				log.Errorf("preparation failed for %s: %v", repoCfg.Name, err)
			}
		}(wCtx, repoCfg)
	}
	return sem.Acquire(ctx, workers)
}

func (s *Stage) objectExists(ctx context.Context, name string) bool {
	objItr := s.RepoHdl.Objects(ctx, &storage.Query{Prefix: name + shared.TarExt})
	_, err := objItr.Next()
	return err == nil
}

func (s *Stage) processGit(ctx context.Context, repoCfg *config.RepoConfig) error {
	var (
		err     error
		repo    *git.Repository
		repoDir string
	)
	if !s.objectExists(ctx, repoCfg.Name) {
		repo, repoDir, err = s.cloneGitRepo(ctx, repoCfg.Name, repoCfg.Address)
	} else {
		repo, repoDir, err = s.updateGitRepo(ctx, repoCfg.Name)
	}
	if repoDir != "" {
		defer func() {
			if err := os.RemoveAll(repoDir); err != nil {
				log.Errorf("failed to remove local repo: %v", err)
			}
		}()
	}

	if err != nil {
		return fmt.Errorf("failed to clone/update repo: %w", err)
	}

	comItr, err := repo.CommitObjects()
	if err != nil {
		return fmt.Errorf("failed to get commit objects: %w", err)
	}
	allCommits := make(map[plumbing.Hash]*object.Commit)
	comItr.ForEach(func(c *object.Commit) error {
		allCommits[c.Hash] = c
		return nil
	})

	commitTracker := make(map[plumbing.Hash]bool)
	// repoInfo is used as the iterator function to create RepositoryInformation structs.
	repoInfo := func(ref *plumbing.Reference) error {
		// Resolve the real commit hash
		commitHash, err := repo.ResolveRevision(plumbing.Revision(ref.Name().String()))

		if err != nil {
			log.Errorf("Failed to resolve %s: %v", ref.Name().String(), err)
			// Ignore errors as this will block the iteration otherwise.
			return nil
		}

		found, err := s.Checker.Exists(ctx, repoCfg.Address, shared.MD5, ref.Hash())
		if err != nil {
			return err
		}
		if found {
			return nil
		}

		var when time.Time
		if c, ok := allCommits[*commitHash]; ok {
			when = c.Author.When
		}

		commitTag := ref.Name().String()

		result := &Result{
			Name:    repoCfg.Name,
			BaseCPE: repoCfg.BaseCPE,
			CheckoutOptions: &git.CheckoutOptions{
				Branch: ref.Name(),
			},
			When:      when,
			Commit:    *commitHash,
			Reference: ref.Hash(),
			CommitTag: commitTag,
			Type:      shared.Git,
			Addr:      repoCfg.Address,
			FileExts:  repoCfg.FileExts,
		}
		commitTracker[*commitHash] = true
		buf, err := json.Marshal(result)
		if err != nil {
			return err
		}

		log.Infof("publishing %s at version: %s", result.Name, commitTag)
		pubRes := s.Output.Publish(ctx, &pubsub.Message{Data: buf})
		_, err = pubRes.Get(ctx)
		return err
	}

	repoItr, err := repo.Tags()
	if err != nil {
		return err
	}
	if err := repoItr.ForEach(repoInfo); err != nil {
		return err
	}

	if repoCfg.BranchVersioning {
		repoItr, err := repo.Branches()
		if err != nil {
			return err
		}
		if err := repoItr.ForEach(repoInfo); err != nil {
			return err
		}
	}

	if repoCfg.HashAllCommits {
		for h, c := range allCommits {
			if found := commitTracker[h]; !found {
				exists, err := s.Checker.Exists(ctx, repoCfg.Address, shared.MD5, h)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				result := &Result{
					Name: repoCfg.Name,
					CheckoutOptions: &git.CheckoutOptions{
						Hash:  h,
						Force: true,
					},
					Reference: h,
					When:      c.Author.When,
					Commit:    h,
					Type:      shared.Git,
					FileExts:  repoCfg.FileExts,
				}
				buf, err := json.Marshal(result)
				if err != nil {
					return err
				}
				pubRes := s.Output.Publish(ctx, &pubsub.Message{Data: buf})
				_, err = pubRes.Get(ctx)
				return err
			}
		}
	}
	return nil
}

func (s *Stage) cloneGitRepo(ctx context.Context, name, address string) (*git.Repository, string, error) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create tmp dir: %v", err)
	}

	repo, err := git.PlainClone(tmpDir, false, &git.CloneOptions{
		URL: address,
	})
	if err != nil {
		return nil, tmpDir, fmt.Errorf("failed to clone repository for %s: %v", name, err)
	}
	return repo, tmpDir, s.copyToBucket(ctx, tmpDir, name)
}

func (s *Stage) updateGitRepo(ctx context.Context, name string) (*git.Repository, string, error) {
	repoDir, err := shared.CopyFromBucket(ctx, s.RepoHdl, name)
	if err != nil {
		return nil, "", err
	}
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		log.Error(err)
		return nil, "", err
	}
	if err := repo.Fetch(&git.FetchOptions{
		Tags: git.AllTags,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		log.Errorf("failed to fetch '%s' with %v", name, err)
		return nil, "", err
	}
	if err := s.copyToBucket(ctx, repoDir, name); err != nil {
		return nil, repoDir, err
	}
	return repo, repoDir, nil
}

func (r *Stage) copyToBucket(ctx context.Context, dir, name string) error {
	var filePaths []string
	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		filePaths = append(filePaths, path)
		return nil
	}); err != nil {
		return fmt.Errorf("failed to collect paths for %s: %v", name, err)
	}

	obj := r.RepoHdl.Object(name + shared.TarExt)
	objW := obj.NewWriter(ctx)
	defer objW.Close()
	tarW := tar.NewWriter(objW)
	defer tarW.Close()

	for _, p := range filePaths {
		buf, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("failed to read file %s for %s: %v", p, name, err)
		}
		if err := tarW.WriteHeader(&tar.Header{
			Name: strings.ReplaceAll(p, dir, ""),
			Mode: 0660,
			Size: int64(len(buf)),
		}); err != nil {
			return fmt.Errorf("failed to write file header for %s to tar archive for %s: %v", p, name, err)
		}
		if _, err := tarW.Write(buf); err != nil {
			return fmt.Errorf("failed to write file %s for tar archive %s: %v", p, name, err)
		}
	}
	return nil
}
