// Package preparation provides functionality to extract tags, branches and commits from repository configurations.
package preparation

import (
	"archive/tar"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/osv.dev/docker/indexer/shared"

	log "github.com/golang/glog"
	pb "github.com/google/osv.dev/docker/indexer/proto"
)

const workers = 5

// Result is the data structure returned by the stage.
type Result struct {
	Name            string
	BaseCPE         string
	VersionRE       *regexp.Regexp
	TagMatching     bool
	BranchMatching  bool
	CheckoutOptions *git.CheckoutOptions
	Commit          plumbing.Hash
	When            time.Time
	Type            pb.RepositoryType
	FileExts        []string
}

// Checker interface is used to check whether a name/hash pair already exists in storage.
type Checker interface {
	Exists(ctx context.Context, name string, hash plumbing.Hash) (bool, error)
}

// Stage holds the data types necessary to process repository configuration.
type Stage struct {
	Checker Checker
	RepoHdl *storage.BucketHandle
}

// Run runs the stage and outputs Result data types to the results channel. 
func (s *Stage) Run(ctx context.Context, cfgs []*pb.Repository, results chan *Result) error {
	var err error
	wErr := make(chan error, workers)
	wg := sync.WaitGroup{}
	routineCtr := 0
	wCtx, wCancel := context.WithCancel(ctx)
	for _, repoCfg := range cfgs {
		if routineCtr >= workers {
			wg.Wait()
			routineCtr = 0
		}
		go func(ctx context.Context, repoCfg *pb.Repository, results chan *Result, errCh chan error) {
			defer wg.Done()

			var err error
			select {
			case <-ctx.Done():
				errCh <- context.Canceled
				return
			default:
			}
			log.Infof("received config for %s", repoCfg.Name)
			switch repoCfg.Type {
			case pb.RepositoryType_GIT:
				err = s.processGit(ctx, repoCfg, results)
			default:
				errCh <- fmt.Errorf("unsupported repository type %s", repoCfg.Type.String())
			}
			if err != nil {
				wErr <- err
			}
		}(wCtx, repoCfg, results, wErr)

		wg.Add(1)
		routineCtr++
		select {
		case err = <-wErr:
			wCancel()
		default:
		}
		if err != nil {
			break
		}
	}
	wg.Wait()
	wCancel()
	return err
}

func (s *Stage) objectExists(ctx context.Context, name string) bool {
	objItr := s.RepoHdl.Objects(ctx, &storage.Query{Prefix: name + shared.TarExt})
	_, err := objItr.Next()
	return err == nil

}

func (s *Stage) processGit(ctx context.Context, repoCfg *pb.Repository, results chan *Result) error {
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
		return err
	}

	comItr, err := repo.CommitObjects()
	if err != nil {
		return err
	}
	allCommits := make(map[plumbing.Hash]*object.Commit)
	comItr.ForEach(func(c *object.Commit) error {
		allCommits[c.Hash] = c
		return nil
	})

	commitTracker := make(map[plumbing.Hash]bool)
	// repoInfo is used as the iterator function to create RepositoryInformation structs.
	repoInfo := func(ref *plumbing.Reference) error {
		found, err := s.Checker.Exists(ctx, repoCfg.Name, ref.Hash())
		if err != nil {
			return err
		}
		if found {
			return nil
		}

		var when time.Time
		if c, ok := allCommits[ref.Hash()]; ok {
			when = c.Author.When
		}
		versRE, err := regexp.Compile(repoCfg.VersionRegex)
		if err != nil {
			return err
		}
		results <- &Result{
			Name:        repoCfg.Name,
			BaseCPE:     repoCfg.BaseCpe,
			VersionRE:   versRE,
			TagMatching: true,
			CheckoutOptions: &git.CheckoutOptions{
				Branch: ref.Name(),
				Force:  true,
			},
			When:     when,
			Commit:   ref.Hash(),
			Type:     pb.RepositoryType_GIT,
			FileExts: repoCfg.FileExtensions,
		}
		commitTracker[ref.Hash()] = true
		return nil
	}
	if repoCfg.GetBranchVersioning() {
		repoItr, err := repo.Branches()
		if err != nil {
			return err
		}
		if err := repoItr.ForEach(repoInfo); err != nil {
			return err
		}
	}
	if repoCfg.GetTagVersioning() {
		repoItr, err := repo.Tags()
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
				exists, err := s.Checker.Exists(ctx, repoCfg.Name, h)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
				results <- &Result{
					Name: repoCfg.Name,
					CheckoutOptions: &git.CheckoutOptions{
						Hash:  h,
						Force: true,
					},
					When:     c.Author.When,
					Commit:   h,
					Type:     pb.RepositoryType_GIT,
					FileExts: repoCfg.FileExtensions,
				}
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
	if err := repo.Fetch(&git.FetchOptions{}); err != nil && err != git.NoErrAlreadyUpToDate {
		log.Error(err)
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
