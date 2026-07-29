package importer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path"
	"strings"

	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

type gitSourceRecord struct {
	client  gitter.Client
	repoURL string
	commit  string
	path    string
}

var _ SourceRecord = gitSourceRecord{}

// Open retrieves uncompressed file content from Gitter for the target commit and path.
func (g gitSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	resp, err := g.client.GetFileContent(ctx, &pb.FileContentRequest{
		Url:    g.repoURL,
		Commit: g.commit,
		Path:   g.path,
	})
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(resp.GetContent())), nil
}

// makeGitPathFilter path filtering function based on the SourceRepository rules.
func makeGitPathFilter(sourceRepo *models.SourceRepository) func(string) string {
	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)

	return func(p string) string {
		if p == "" {
			return ""
		}
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
}

// fetchGitterFileDiffs requests file diffs from Gitter for a repo.
// When lastSyncedCommit is empty, Gitter diffs against an empty tree to return all files in the repo as "add"
func fetchGitterFileDiffs(ctx context.Context, client gitter.Client, sourceRepo *models.SourceRepository, lastSyncedCommit string) (*pb.FileDiffsResponse, error) {
	req := &pb.FileDiffsRequest{
		Url:              sourceRepo.Git.URL,
		LastSyncedCommit: lastSyncedCommit,
		Branch:           sourceRepo.Git.Branch,
	}

	return client.GetFileDiffs(ctx, req)
}

func handleImportGit(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeGit || sourceRepo.Git == nil {
		return errors.New("invalid SourceRepository for git import")
	}
	if config.GitterClient == nil {
		return errors.New("gitter client is required for git import")
	}
	logger.InfoContext(ctx, "Importing git source repository",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.Git.URL))

	resp, err := fetchGitterFileDiffs(ctx, config.GitterClient, sourceRepo, sourceRepo.Git.LastSyncedCommit)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get file diffs from gitter",
			slog.Any("error", err), slog.String("source", sourceRepo.Name))

		return err
	}

	format := extensionToFormat(sourceRepo.Extension)
	isReimport := sourceRepo.Git.LastSyncedCommit == ""
	filterPath := makeGitPathFilter(sourceRepo)
	latestCommit := resp.GetLatestCommit()

	for _, fileChange := range resp.GetChanges() {
		if err := ctx.Err(); err != nil {
			return err
		}
		from := filterPath(fileChange.GetFromPath())
		to := filterPath(fileChange.GetToPath())
		if from == "" && to == "" {
			// file was ignored/removed in both commits
			continue
		}
		pool := sourceRepo.WorkPool
		if isReimport {
			pool = config.ReimportTaskPool
		}
		if to == "" {
			// Object was deleted / moved to ignored
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- WorkItem{
				Context: ctx,
				SourceRecord: gitSourceRecord{
					client:  config.GitterClient,
					repoURL: sourceRepo.Git.URL,
					commit:  latestCommit,
					path:    from,
				},
				SourceRepository: sourceRepo.Name,
				SourcePath:       from,
				Action:           ActionWithdraw,
				Strict:           sourceRepo.Strictness,
				Format:           format,
				KeyPath:          sourceRepo.KeyPath,
				IsReimport:       isReimport,
				WorkPool:         pool,
			}:
			}

			continue
		}
		// object created/modified - send to channel
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- WorkItem{
			Context: ctx,
			SourceRecord: gitSourceRecord{
				client:  config.GitterClient,
				repoURL: sourceRepo.Git.URL,
				commit:  latestCommit,
				path:    to,
			},
			SourceRepository: sourceRepo.Name,
			SourcePath:       to,
			Format:           format,
			KeyPath:          sourceRepo.KeyPath,
			IsReimport:       isReimport,
			Strict:           sourceRepo.Strictness,
			WorkPool:         pool,
		}:
		}
	}

	sourceRepo.Git.LastSyncedCommit = latestCommit
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.ErrorContext(ctx, "Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))

		return err
	}
	logger.InfoContext(ctx, "Finished importing git source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.Git.URL))

	return nil
}

func handleReconcileGit(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeGit || sourceRepo.Git == nil {
		return errors.New("invalid SourceRepository for git reconcile")
	}
	if config.GitterClient == nil {
		return errors.New("gitter client is required for git reconcile")
	}
	logger.InfoContext(ctx, "Processing git reconcile",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.Git.URL))

	// Fetch datastore records for the source
	dbRecords, err := fetchDBRecords(ctx, config, sourceRepo)
	if err != nil {
		return err
	}

	format := extensionToFormat(sourceRepo.Extension)

	// Query Gitter with empty lastSyncedCommit to get all files in the repository
	resp, err := fetchGitterFileDiffs(ctx, config.GitterClient, sourceRepo, "")
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.ErrorContext(ctx, "Failed to get file diffs for git reconcile", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		}

		return err
	}

	filterPath := makeGitPathFilter(sourceRepo)
	latestCommit := resp.GetLatestCommit()

	for _, fileChange := range resp.GetChanges() {
		if err := ctx.Err(); err != nil {
			return err
		}

		relPath := filterPath(fileChange.GetToPath())
		if relPath == "" {
			continue
		}

		sourceRecord := gitSourceRecord{
			client:  config.GitterClient,
			repoURL: sourceRepo.Git.URL,
			commit:  latestCommit,
			path:    relPath,
		}

		checkReconcile(ctx, ch, sourceRepo, dbRecords, relPath, nil, sourceRecord, format, config.ReimportTaskPool)
	}

	logger.InfoContext(ctx, "Finished reconciling git source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.Git.URL))

	return nil
}
