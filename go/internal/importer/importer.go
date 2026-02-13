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

	SourceRepoStore models.SourceRepositoryStore
	Publisher       clients.Publisher
	GCSProvider     clients.CloudStorageProvider
	HTTPClient      *http.Client
	GitWorkDir      string

	StrictValidation bool
}

type RetryableHTTPLeveledLogger struct{}

var _ retryablehttp.LeveledLogger = RetryableHTTPLeveledLogger{}

func (r RetryableHTTPLeveledLogger) Error(msg string, keysAndValues ...interface{}) {
	logger.Error(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Info(msg string, keysAndValues ...interface{}) {
	logger.Info(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Debug(msg string, keysAndValues ...interface{}) {
	logger.Debug(msg, keysAndValues...)
}

func (r RetryableHTTPLeveledLogger) Warn(msg string, keysAndValues ...interface{}) {
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
					logger.Error("Failed to import git source repository", slog.Any("error", err), slog.String("source_repository", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeBucket:
				if err := handleImportBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to import bucket source repository", slog.Any("error", err), slog.String("source_repository", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleImportREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.Error("Failed to import REST source repository", slog.Any("error", err), slog.String("source_repository", sourceRepo.Name))
				}
			default:
				logger.Error("Unsupported source repository type", slog.String("source_repository", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
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
	Open(context.Context) (io.ReadCloser, error)
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
			r, err := sourceRecord.Open(ctx)
			sourceRepoName := sourceRecord.SourceRepository()
			if err != nil {
				logger.Error("Failed to open source record",
					slog.Any("error", err),
					slog.String("source_repository", sourceRepoName),
					slog.String("source_path", sourceRecord.SourcePath()))
				continue
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				logger.Error("Failed to read source record",
					slog.Any("error", err),
					slog.String("source_repository", sourceRepoName),
					slog.String("source_path", sourceRecord.SourcePath()))
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
						slog.String("source_repository", sourceRepoName),
						slog.String("source_path", sourceRecord.SourcePath()))
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
							slog.String("source_repository", sourceRepoName),
							slog.String("source_path", sourceRecord.SourcePath()))
						continue
					}
					data = []byte(res.Raw)
				}
				if err := protojson.Unmarshal(data, &vulnProto); err != nil {
					logger.Error("Failed to unmarshal OSV proto",
						slog.Any("error", err),
						slog.String("source_repository", sourceRepoName),
						slog.String("source_path", sourceRecord.SourcePath()))
					continue
				}

			}
			// Skip if the record is older than the last update time
			modified := vulnProto.Modified.AsTime()
			if t, ok := sourceRecord.LastUpdated(); ok {
				if t.After(modified) {
					continue
				}
			}
			if err := sendToWorker(ctx, config, sourceRecord, hash, modified); err != nil {
				logger.Error("Failed to send to worker", slog.Any("error", err), slog.String("source_repository", sourceRepoName), slog.String("source_path", sourceRecord.SourcePath()))
			}
		}
	}
}

func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func sendToWorker(ctx context.Context, config Config, sourceRecord SourceRecord, hash string, modifiedTime time.Time) error {
	msg := &pubsub.Message{
		Data: []byte(""),
		Attributes: map[string]string{
			"type":            "update",
			"source":          sourceRecord.SourceRepository(),
			"path":            sourceRecord.SourcePath(),
			"original_sha256": hash,
			"deleted":         "false", // TODO
			"req_timestamp":   strconv.FormatInt(time.Now().Unix(), 10),
		},
	}
	if sourceRecord.ShouldSendModifiedTime() {
		msg.Attributes["src_timestamp"] = strconv.FormatInt(modifiedTime.Unix(), 10)
	}
	result := config.Publisher.Publish(ctx, msg)
	_, err := result.Get(ctx)
	return err
}
