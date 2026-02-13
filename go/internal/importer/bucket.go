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
	bucket           clients.CloudStorage
	objectPath       string
	keyPath          string
	hasUpdateTime    bool
	lastUpdated      time.Time
	format           RecordFormat
	sourceRepository string
}

var _ SourceRecord = bucketSourceRecord{}

func (b bucketSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	data, err := b.bucket.ReadObject(ctx, b.objectPath)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b bucketSourceRecord) KeyPath() string {
	return b.keyPath
}

func (b bucketSourceRecord) Format() RecordFormat {
	return b.format
}

func (b bucketSourceRecord) LastUpdated() (time.Time, bool) {
	return b.lastUpdated, b.hasUpdateTime
}

func (b bucketSourceRecord) SourceRepository() string {
	return b.sourceRepository
}

func (b bucketSourceRecord) SourcePath() string {
	return b.objectPath
}

func (b bucketSourceRecord) ShouldSendModifiedTime() bool {
	return b.hasUpdateTime
}

func handleImportBucket(ctx context.Context, ch chan<- SourceRecord, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeBucket || sourceRepo.Bucket == nil {
		return errors.New("invalid SourceRepository for bucket import")
	}
	logger.Info("Importing bucket source repository",
		slog.String("source_repository", sourceRepo.Name), slog.String("bucket", sourceRepo.Bucket.Name))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	bucket := config.GCSProvider.Bucket(sourceRepo.Bucket.Name)
	hasUpdateTime := false
	var lastUpdated time.Time
	if !sourceRepo.Bucket.IgnoreLastImportTime && sourceRepo.Bucket.LastUpdated != nil {
		lastUpdated = *sourceRepo.Bucket.LastUpdated
		hasUpdateTime = true
	}
	format := RecordFormatUnknown
	if strings.ToLower(sourceRepo.Extension) == ".yaml" || strings.ToLower(sourceRepo.Extension) == ".yml" {
		format = RecordFormatYAML
	} else if strings.ToLower(sourceRepo.Extension) == ".json" {
		format = RecordFormatJSON
	}
	timeOfRun := time.Now()
	for obj, err := range bucket.Objects(ctx, sourceRepo.Bucket.Path) {
		if err != nil {
			return err
		}
		if hasUpdateTime {
			if obj.Attrs.CustomTime.Before(lastUpdated) {
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
		ch <- bucketSourceRecord{
			bucket:           bucket,
			objectPath:       obj.Name,
			lastUpdated:      lastUpdated,
			hasUpdateTime:    hasUpdateTime,
			format:           format,
			keyPath:          sourceRepo.KeyPath,
			sourceRepository: sourceRepo.Name,
		}
	}

	sourceRepo.Bucket.LastUpdated = &timeOfRun
	sourceRepo.Bucket.IgnoreLastImportTime = false
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.Error("Failed to update source repository", slog.Any("error", err), slog.String("source_repository", sourceRepo.Name))
		return err
	}
	logger.Info("Finished importing bucket source repository",
		slog.String("source_repository", sourceRepo.Name),
		slog.String("bucket", sourceRepo.Bucket.Name))

	return nil
}
