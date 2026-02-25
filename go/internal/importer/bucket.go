package importer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

type bucketSourceRecord struct {
	bucket     clients.CloudStorage
	objectPath string
}

var _ SourceRecord = bucketSourceRecord{}

func (b bucketSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	data, err := b.bucket.ReadObject(ctx, b.objectPath)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

func handleImportBucket(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeBucket || sourceRepo.Bucket == nil {
		return errors.New("invalid SourceRepository for bucket import")
	}
	logger.InfoContext(ctx, "Importing bucket source repository",
		slog.String("source", sourceRepo.Name), slog.String("bucket", sourceRepo.Bucket.Name))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	bucket := config.GCSProvider.Bucket(sourceRepo.Bucket.Name)
	hasUpdateTime := false
	var lastUpdated time.Time
	if !sourceRepo.Bucket.IgnoreLastImportTime && sourceRepo.Bucket.LastUpdated != nil {
		lastUpdated = *sourceRepo.Bucket.LastUpdated
		hasUpdateTime = true
	}
	format := extensionToFormat(sourceRepo.Extension)
	timeOfRun := time.Now()
	for obj, err := range bucket.Objects(ctx, sourceRepo.Bucket.Path) {
		if err != nil {
			return err
		}
		if hasUpdateTime {
			if obj.Attrs.Updated.Before(lastUpdated) || obj.Attrs.Updated.Equal(lastUpdated) {
				continue
			}
		}
		if !strings.HasSuffix(obj.Name, sourceRepo.Extension) {
			continue
		}
		base := path.Base(obj.Name)
		if shouldIgnore(base, sourceRepo.IDPrefixes, compiledIgnorePatterns) {
			continue
		}
		ch <- WorkItem{
			Context: ctx,
			SourceRecord: bucketSourceRecord{
				bucket:     bucket,
				objectPath: obj.Name,
			},
			SourceRepository: sourceRepo.Name,
			SourcePath:       obj.Name,
			LastUpdated:      lastUpdated,
			HasLastUpdated:   hasUpdateTime,
			Format:           format,
			KeyPath:          sourceRepo.KeyPath,
			Strict:           sourceRepo.Strictness,
			IsReimport:       !hasUpdateTime,
		}
	}

	sourceRepo.Bucket.LastUpdated = &timeOfRun
	sourceRepo.Bucket.IgnoreLastImportTime = false
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.ErrorContext(ctx, "Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	logger.InfoContext(ctx, "Finished importing bucket source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("bucket", sourceRepo.Bucket.Name))

	return nil
}

func handleDeleteBucket(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeBucket || sourceRepo.Bucket == nil {
		return errors.New("invalid SourceRepository for bucket deletion")
	}

	logger.InfoContext(ctx, "Processing bucket deletions",
		slog.String("source", sourceRepo.Name), slog.String("bucket", sourceRepo.Bucket.Name))

	// Get all objects in the bucket
	bucket := config.GCSProvider.Bucket(sourceRepo.Bucket.Name)
	objectsInBucket := make(map[string]bool)
	for obj, err := range bucket.Objects(ctx, sourceRepo.Bucket.Path) {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(obj.Name, sourceRepo.Extension) {
			continue
		}
		objectsInBucket[obj.Name] = true
	}

	// Get all non-withdrawn vulnerabilities in Datastore for this source
	vulnsInDatastore := make([]*models.VulnSourceRef, 0, len(objectsInBucket))
	for entry, err := range config.VulnerabilityStore.ListBySource(ctx, sourceRepo.Name, true) {
		if err != nil {
			return err
		}
		vulnsInDatastore = append(vulnsInDatastore, entry)
	}

	if len(vulnsInDatastore) == 0 {
		logger.InfoContext(ctx, "No vulnerabilities found in Datastore for source", slog.String("source", sourceRepo.Name))
		return nil
	}

	// Reconcile
	var toDelete []*models.VulnSourceRef
	for _, entry := range vulnsInDatastore {
		if !objectsInBucket[entry.Path] {
			toDelete = append(toDelete, entry)
		}
	}

	if len(toDelete) == 0 {
		logger.InfoContext(ctx, "No vulnerabilities to delete", slog.String("source", sourceRepo.Name))
		return nil
	}

	// Safety Check
	threshold := config.DeleteThreshold
	if sourceRepo.Bucket.IgnoreDeletionThreshold {
		threshold = 101.0
	}
	percentage := (float64(len(toDelete)) / float64(len(vulnsInDatastore))) * 100.0
	if percentage >= threshold {
		logger.ErrorContext(ctx, "Cowardly refusing to delete missing records (threshold exceeded)",
			slog.String("source", sourceRepo.Name),
			slog.Int("to_delete", len(toDelete)),
			slog.Int("total", len(vulnsInDatastore)),
			slog.Float64("percentage", percentage),
			slog.Float64("threshold", threshold))

		return errors.New("deletion threshold exceeded")
	}

	// Trigger deletions
	for _, entry := range toDelete {
		ch <- WorkItem{
			Context: ctx,
			SourceRecord: bucketSourceRecord{
				bucket:     bucket,
				objectPath: entry.Path,
			},
			SourceRepository: entry.Source,
			SourcePath:       entry.Path,
			IsDeleted:        true,
		}
	}

	return nil
}
