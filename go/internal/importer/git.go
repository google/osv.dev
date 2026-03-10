package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/repos"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/singleflight"
)

type gitSourceRecord struct {
	repo   sharedRepo
	commit *object.Commit
	path   string
}

var _ SourceRecord = gitSourceRecord{}

func (g gitSourceRecord) Open(_ context.Context) (io.ReadCloser, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	f, err := g.commit.File(g.path)
	if err != nil {
		return nil, err
	}
	// read out the whole file so that the mutex is not held for too long
	reader, err := f.Reader()
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(content)), nil
}

// Some sourceRepository entries share the same git repository (e.g. ubuntu).
// We use singleflight.Group to share the repository between them.
var repoGroup singleflight.Group

type sharedRepo struct {
	*git.Repository

	mu *sync.Mutex
}

func handleImportGit(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeGit || sourceRepo.Git == nil {
		return errors.New("invalid SourceRepository for git import")
	}
	logger.InfoContext(ctx, "Importing git source repository",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.Git.URL))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	repoInterface, err, _ := repoGroup.Do(sourceRepo.Git.URL, func() (any, error) {
		// Temporary migration from Python to Go
		// TODO(michaelkedar): Remove when python is gone
		// If the sha name of the repo doesn't exist, check if the source repo name exists from python.
		// If it does, move it and use it.
		sha := sha256.Sum256([]byte(sourceRepo.Git.URL))
		path := hex.EncodeToString(sha[:])
		path = filepath.Join(config.GitWorkDir, path)
		if _, err := os.Stat(path); err != nil {
			pythonPath := filepath.Join(config.GitWorkDir, sourceRepo.Name)
			if _, err := os.Stat(pythonPath); err == nil {
				// try rename it, but don't error if it fails
				_ = os.Rename(pythonPath, path)
			}
		}
		repo, err := repos.CloneToDir(ctx, sourceRepo.Git.URL, path, true)
		if err != nil {
			return nil, err
		}

		return sharedRepo{
			Repository: repo,
			mu:         &sync.Mutex{},
		}, nil
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to clone git source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	repo := repoInterface.(sharedRepo)

	format := extensionToFormat(sourceRepo.Extension)
	isReimport := sourceRepo.Git.LastSyncedCommit == ""

	changedFiles, commit, err := changedFiles(ctx, repo, sourceRepo)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get changed files", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	filterPath := func(p string) string {
		if !strings.HasSuffix(p, sourceRepo.Extension) {
			return ""
		}
		if dirPath := sourceRepo.Git.Path; dirPath != "" {
			if !strings.HasSuffix(dirPath, "/") {
				dirPath += "/"
			}
			if !strings.HasPrefix(p, dirPath) {
				return ""
			}
		}
		if shouldIgnore(path.Base(p), sourceRepo.IDPrefixes, compiledIgnorePatterns) {
			return ""
		}

		return p
	}
	for _, fileChange := range changedFiles {
		from := filterPath(fileChange.from)
		to := filterPath(fileChange.to)
		if from == "" && to == "" {
			// file was ignored/removed in both commits
			continue
		}
		if to == "" {
			// Object was deleted / moved to ignored
			ch <- WorkItem{
				Context: ctx,
				SourceRecord: gitSourceRecord{
					path: from,
					repo: repo,
				},
				SourceRepository: sourceRepo.Name,
				SourcePath:       from,
				IsDeleted:        true,
				Strict:           sourceRepo.Strictness,
				Format:           format,
				KeyPath:          sourceRepo.KeyPath,
				IsReimport:       isReimport,
			}

			continue
		}
		// object created/modified - send to channel
		ch <- WorkItem{
			Context: ctx,
			SourceRecord: gitSourceRecord{
				repo:   repo,
				commit: commit,
				path:   to,
			},
			SourceRepository: sourceRepo.Name,
			SourcePath:       to,
			Format:           format,
			KeyPath:          sourceRepo.KeyPath,
			IsReimport:       isReimport,
			Strict:           sourceRepo.Strictness,
		}
	}

	sourceRepo.Git.LastSyncedCommit = commit.Hash.String()
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.ErrorContext(ctx, "Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	logger.InfoContext(ctx, "Finished importing git source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.Git.URL))

	return nil
}

type fileChange struct {
	from string
	to   string
}

func changedFiles(ctx context.Context, repo sharedRepo, sourceRepo *models.SourceRepository) ([]fileChange, *object.Commit, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	var current plumbing.Hash
	if sourceRepo.Git.Branch != "" {
		ref, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", sourceRepo.Git.Branch), true)
		if err != nil {
			return nil, nil, err
		}
		current = ref.Hash()
	} else {
		ref, err := repo.Reference(plumbing.NewRemoteHEADReferenceName("origin"), true)
		if err != nil {
			return nil, nil, err
		}
		current = ref.Hash()
	}
	currentCommit, err := repo.CommitObject(current)
	if err != nil {
		return nil, nil, err
	}
	currentTree, err := currentCommit.Tree()
	if err != nil {
		return nil, nil, err
	}
	var prevSyncTree *object.Tree
	if sourceRepo.Git.LastSyncedCommit != "" {
		prevSyncCommit, err := repo.CommitObject(plumbing.NewHash(sourceRepo.Git.LastSyncedCommit))
		if err != nil {
			return nil, nil, err
		}
		prevSyncTree, err = prevSyncCommit.Tree()
		if err != nil {
			return nil, nil, err
		}
	}
	// tree.Diff(nil) returns all files, which is what we want.
	diff, err := currentTree.DiffContext(ctx, prevSyncTree)
	if err != nil {
		return nil, nil, err
	}
	changedFiles := make([]fileChange, 0, len(diff))
	for _, d := range diff {
		// Note: since we're doing child.Diff(parent), to/from are reversed from what you might expect.
		changedFiles = append(changedFiles, fileChange{
			from: d.To.Name,
			to:   d.From.Name,
		})
	}

	return changedFiles, currentCommit, nil
}

type localFileSourceRecord struct {
	path string
}

func (r localFileSourceRecord) Open(_ context.Context) (io.ReadCloser, error) {
	return os.Open(r.path)
}

func handleReconcileGit(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeGit || sourceRepo.Git == nil {
		return errors.New("invalid SourceRepository for git reconcile")
	}
	logger.InfoContext(ctx, "Processing git reconcile",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.Git.URL))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)

	sha := sha256.Sum256([]byte(sourceRepo.Git.URL))
	pathStr := hex.EncodeToString(sha[:])
	pathStr = filepath.Join(config.GitWorkDir, pathStr)

	// TODO: We don't support multiple sources with the same repo but different branches.
	_, err, _ := repoGroup.Do(sourceRepo.Git.URL, func() (any, error) {
		repo, err := repos.CloneToDir(ctx, sourceRepo.Git.URL, pathStr, true)
		if err != nil {
			return nil, err
		}

		if sourceRepo.Git.Branch != "" {
			wt, err := repo.Worktree()
			if err == nil {
				_ = wt.Checkout(&git.CheckoutOptions{
					Branch: plumbing.NewRemoteReferenceName("origin", sourceRepo.Git.Branch),
					Force:  true,
				})
			}
		}

		return sharedRepo{
			Repository: repo,
			mu:         &sync.Mutex{},
		}, nil
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to clone git source repository for reconcile", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}

	// Fetch datastore records for the source
	dbRecords, err := fetchDBRecords(ctx, config, sourceRepo)
	if err != nil {
		return err
	}

	format := extensionToFormat(sourceRepo.Extension)

	searchDir := pathStr
	if sourceRepo.Git.Path != "" {
		searchDir = filepath.Join(pathStr, sourceRepo.Git.Path)
	}

	err = filepath.WalkDir(searchDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(p, sourceRepo.Extension) {
			return nil
		}

		relPath, err := filepath.Rel(pathStr, p)
		if err != nil {
			return err
		}
		// Always use forward slashes for relative paths inside git repositories
		relPath = filepath.ToSlash(relPath)

		if shouldIgnore(path.Base(p), sourceRepo.IDPrefixes, compiledIgnorePatterns) {
			return nil
		}

		sourceRecord := localFileSourceRecord{
			path: p, // Absolute path on disk
		}

		checkReconcile(ctx, ch, sourceRepo, dbRecords, relPath, nil, sourceRecord, format)

		return nil
	})

	if err != nil {
		return err
	}

	logger.InfoContext(ctx, "Finished reconciling git source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.Git.URL))

	return nil
}
