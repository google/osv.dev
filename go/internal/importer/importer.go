// Package importer provides functionality for importing vulnerability records from various sources.
package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const TasksTopic = "tasks"

type Config struct {
	NumWorkers int

	SourceRepoStore    models.SourceRepositoryStore
	VulnerabilityStore models.VulnerabilityStore
	Publisher          clients.Publisher
	GCSProvider        clients.CloudStorageProvider
	HTTPClient         *http.Client
	GitWorkDir         string

	StrictValidation bool
	DeleteThreshold  float64
}

type RetryableHTTPLeveledLogger struct{}

var _ retryablehttp.LeveledLogger = RetryableHTTPLeveledLogger{}

func (r RetryableHTTPLeveledLogger) Error(msg string, keysAndValues ...any) {
	logger.Error(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Info(msg string, keysAndValues ...any) {
	logger.Info(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Debug(msg string, keysAndValues ...any) {
	logger.Debug(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Warn(msg string, keysAndValues ...any) {
	logger.Warn(msg, keysAndValues...)
}

func Run(ctx context.Context, config Config) error {
	logger.Info("Importer started")

	workCh := make(chan SourceRecord)
	var workWg sync.WaitGroup
	for range config.NumWorkers {
		workWg.Go(func() {
			importerWorker(ctx, workCh, config)
		})
	}

	var wg sync.WaitGroup
	for sourceRepo, err := range config.SourceRepoStore.All(ctx) {
		if err != nil {
			return err
		}
		wg.Go(func() {
			switch sourceRepo.Type {
			case models.SourceRepositoryTypeGit:
				if err := handleImportGit(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to import git source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeBucket:
				if err := handleImportBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to import bucket source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleImportREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to import REST source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			default:
				logger.Error("Unsupported source repository type", slog.String("source", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
			}
		})
	}
	wg.Wait()
	close(workCh)
	workWg.Wait()

	return nil
}

func RunDeletions(ctx context.Context, config Config) error {
	logger.Info("Deletion reconciler started")

	workCh := make(chan SourceRecord)
	var workWg sync.WaitGroup
	for range config.NumWorkers {
		workWg.Go(func() {
			importerWorker(ctx, workCh, config)
		})
	}

	var wg sync.WaitGroup
	for sourceRepo, err := range config.SourceRepoStore.All(ctx) {
		if err != nil {
			return err
		}
		wg.Go(func() {
			switch sourceRepo.Type {
			case models.SourceRepositoryTypeGit:
				// Git deletions are handled in regular importer
				return
			case models.SourceRepositoryTypeBucket:
				if err := handleDeleteBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to process bucket deletions", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleDeleteREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to process REST deletions", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			default:
				logger.Error("Unsupported source repository type for deletions", slog.String("source", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
			}
		})
	}
	wg.Wait()
	close(workCh)
	workWg.Wait()

	return nil
}

type RecordFormat int

const (
	RecordFormatUnknown RecordFormat = iota
	RecordFormatJSON
	RecordFormatYAML
)

type SourceRecord interface {
	// Open the source record
	Open(ctx context.Context) (io.ReadCloser, error)
	// KeyPath is the key path to the vulnerability within the source record
	// equal to the SourceRepo.KeyPath
	KeyPath() string
	// Format is the format (json/yaml) of the source record
	Format() RecordFormat
	// LastUpdated is the last updated time of the source record
	LastUpdated() (time.Time, bool)
	// SourceRepository is the name of the source repository
	SourceRepository() string
	// SourcePath is path to the record within the source repository
	SourcePath() string
	// ShouldSendModifiedTime returns true if the modified time should be sent (for latency monitoring)
	ShouldSendModifiedTime() bool
	// IsDeleted returns true if the record was deleted.
	IsDeleted() bool
	// Strictness returns true if strict validation is requested for this record.
	Strictness() bool
}

func importerWorker(ctx context.Context, ch <-chan SourceRecord, config Config) {
	for {
		select {
		case <-ctx.Done():
			return
		case sourceRecord, ok := <-ch:
			if !ok {
				return
			}
			sourceRepoName := sourceRecord.SourceRepository()
			sourcePath := sourceRecord.SourcePath()
			strict := config.StrictValidation && sourceRecord.Strictness()

			unmarshalOptions := protojson.UnmarshalOptions{
				DiscardUnknown: !strict,
			}

			if sourceRecord.IsDeleted() {
				if err := sendDeletionToWorker(ctx, config, sourceRepoName, sourcePath); err != nil {
					logger.Error("Failed to send deletion to worker",
						slog.Any("error", err),
						slog.String("source", sourceRepoName),
						slog.String("path", sourcePath))
				}

				continue
			}

			r, err := sourceRecord.Open(ctx)
			if err != nil {
				logger.Error("Failed to open source record",
					slog.Any("error", err),
					slog.String("source", sourceRepoName),
					slog.String("path", sourcePath))

				continue
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				logger.Error("Failed to read source record",
					slog.Any("error", err),
					slog.String("source", sourceRepoName),
					slog.String("path", sourcePath))

				continue
			}
			hash := computeHash(data)
			var vulnProto osvschema.Vulnerability
			switch sourceRecord.Format() {
			case RecordFormatYAML:
				// convert YAML to JSON, then use JSON logic below
				json, err := yaml.ToJSON(data)
				if err != nil {
					logger.Error("Failed to convert YAML to JSON",
						slog.Any("error", err),
						slog.String("source", sourceRepoName),
						slog.String("path", sourcePath))

					continue
				}
				data = json

				fallthrough
			case RecordFormatJSON:
				// unmarshal JSON to proto
				if keyPath := sourceRecord.KeyPath(); keyPath != "" {
					res := gjson.GetBytes(data, keyPath)
					if !res.Exists() {
						logger.Error("Key path not found",
							slog.String("key_path", keyPath),
							slog.String("source", sourceRepoName),
							slog.String("path", sourcePath))

						continue
					}
					data = []byte(res.Raw)
				}

				if strict {
					if err := Validate(data); err != nil {
						logger.Error("JSON schema validation failed",
							slog.Any("error", err),
							slog.String("source", sourceRepoName),
							slog.String("path", sourcePath))

						continue
					}
				}

				if err := unmarshalOptions.Unmarshal(data, &vulnProto); err != nil {
					logger.Error("Failed to unmarshal OSV proto",
						slog.Any("error", err),
						slog.String("source", sourceRepoName),
						slog.String("path", sourcePath))

					continue
				}
			default:
				logger.Error("Unknown record format",
					slog.String("source", sourceRepoName),
					slog.String("path", sourcePath))

				continue
			}
			// Skip if the record is older than the last update time
			modified := vulnProto.GetModified().AsTime()
			if t, ok := sourceRecord.LastUpdated(); ok {
				if t.After(modified) {
					continue
				}
			}
			if err := sendToWorker(ctx, config, sourceRecord, hash, modified); err != nil {
				logger.Error("Failed to send to worker", slog.Any("error", err), slog.String("source", sourceRepoName), slog.String("path", sourcePath))
			}
		}
	}
}

func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func sendToWorker(ctx context.Context, config Config, sourceRecord SourceRecord, hash string, modifiedTime time.Time) error {
	var srcTimestamp *time.Time
	if sourceRecord.ShouldSendModifiedTime() {
		srcTimestamp = &modifiedTime
	}

	return publishUpdate(ctx, config.Publisher, sourceRecord.SourceRepository(), sourceRecord.SourcePath(), hash, false, srcTimestamp)
}

func sendDeletionToWorker(ctx context.Context, config Config, source, path string) error {
	return publishUpdate(ctx, config.Publisher, source, path, "", true, nil)
}

func publishUpdate(ctx context.Context, publisher clients.Publisher, source, path, hash string, deleted bool, srcTimestamp *time.Time) error {
	msg := &pubsub.Message{
		Data: []byte(""),
		Attributes: map[string]string{
			"type":            "update",
			"source":          source,
			"path":            path,
			"original_sha256": hash,
			"deleted":         strconv.FormatBool(deleted),
			"req_timestamp":   strconv.FormatInt(time.Now().Unix(), 10),
		},
	}
	if srcTimestamp != nil {
		msg.Attributes["src_timestamp"] = strconv.FormatInt(srcTimestamp.Unix(), 10)
	} else {
		msg.Attributes["src_timestamp"] = ""
	}
	result := publisher.Publish(ctx, msg)
	_, err := result.Get(ctx)

	return err
}
