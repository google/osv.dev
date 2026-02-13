package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/repos"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/singleflight"
)

type gitSourceRecord struct {
	repo             sharedRepo
	commit           *object.Commit
	path             string
	keyPath          string
	format           RecordFormat
	sourceRepository string
	shouldSendUpdate bool
}

var _ SourceRecord = gitSourceRecord{}

func (g gitSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
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

func (g gitSourceRecord) KeyPath() string {
	return g.keyPath
}

func (g gitSourceRecord) Format() RecordFormat {
	return g.format
}

func (g gitSourceRecord) LastUpdated() (time.Time, bool) {
	return time.Time{}, false
}

func (g gitSourceRecord) SourceRepository() string {
	return g.sourceRepository
}

func (g gitSourceRecord) SourcePath() string {
	return g.path
}

func (g gitSourceRecord) ShouldSendModifiedTime() bool {
	return g.shouldSendUpdate
}

// Some sourceRepository entries share the same git repository (e.g. ubuntu).
// We use singleflight.Group to share the repository between them.
var repoGroup singleflight.Group

type sharedRepo struct {
	*git.Repository
	mu *sync.Mutex
}

func handleImportGit(ctx context.Context, ch chan<- SourceRecord, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeGit || sourceRepo.Git == nil {
		return errors.New("invalid SourceRepository for git import")
	}
	logger.Info("Importing git source repository",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.Git.URL))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	repoInterface, err, _ := repoGroup.Do(sourceRepo.Git.URL, func() (interface{}, error) {
		// Temporary migration from Python to Go
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
		logger.Error("Failed to clone git source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	repo := repoInterface.(sharedRepo)

	format := RecordFormatUnknown
	if strings.ToLower(sourceRepo.Extension) == ".yaml" || strings.ToLower(sourceRepo.Extension) == ".yml" {
		format = RecordFormatYAML
	} else if strings.ToLower(sourceRepo.Extension) == ".json" {
		format = RecordFormatJSON
	}
	shouldSendUpdate := sourceRepo.Git.LastSyncedCommit != ""

	changedFiles, commit, err := changedFiles(ctx, repo, sourceRepo)
	if err != nil {
		logger.Error("Failed to get changed files", slog.Any("error", err), slog.String("source", sourceRepo.Name))
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
			// TODO: handle deletion
			continue
		}
		// object created/modified - send to channel
		ch <- gitSourceRecord{
			repo:             repo,
			commit:           commit,
			path:             to,
			keyPath:          sourceRepo.KeyPath,
			format:           format,
			sourceRepository: sourceRepo.Name,
			shouldSendUpdate: shouldSendUpdate,
		}
	}

	sourceRepo.Git.LastSyncedCommit = commit.Hash.String()
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.Error("Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	logger.Info("Finished importing git source repository",
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
		ref, err := repo.Head()
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
	var changedFiles []fileChange
	for _, d := range diff {
		// Note: since we're doing child.Diff(parent), to/from are reversed from what you might expect.
		changedFiles = append(changedFiles, fileChange{
			from: d.To.Name,
			to:   d.From.Name,
		})
	}
	return changedFiles, currentCommit, nil
}
