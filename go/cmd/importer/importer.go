package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// publisher is a mockable interface for publishing messages to a topic.
type publisher interface {
	Publish(ctx context.Context, msg *pubsub.Message) *pubsub.PublishResult
}

const tasksTopic = "tasks"

type ImporterConfig struct {
	NumWorkers int

	SourceRepoStore models.SourceRepositoryStore
	Publisher       publisher
	GCSClient       *storage.Client
	HTTPClient      *http.Client
	GitWorkDir      string

	StrictValidation bool
}

type retryableHTTPLeveledLogger struct{}

var _ retryablehttp.LeveledLogger = retryableHTTPLeveledLogger{}

func (r retryableHTTPLeveledLogger) Error(msg string, keysAndValues ...interface{}) {
	logger.Error(msg, keysAndValues...)
}

func (r retryableHTTPLeveledLogger) Info(msg string, keysAndValues ...interface{}) {
	logger.Info(msg, keysAndValues...)
}

func (r retryableHTTPLeveledLogger) Debug(msg string, keysAndValues ...interface{}) {
	logger.Debug(msg, keysAndValues...)
}

func (r retryableHTTPLeveledLogger) Warn(msg string, keysAndValues ...interface{}) {
	logger.Warn(msg, keysAndValues...)
}

func main() {
	logger.InitGlobalLogger()

	strictValidation := flag.Bool("strict-validation", false, "Fail to import entries that do not pass validation.")
	delete := flag.Bool("delete", false, "Bypass importing and propagate record deletions from source to Datastore")
	deleteThresholdPct := flag.Float64("delete-threshold-pct", 10.0, "More than this percent of records for a given source being deleted triggers an error")
	workDir := flag.String("work-dir", "/work", "Work directory for git repos")
	numWorkers := flag.Int("num-workers", 50, "Number of workers to use for importing")

	flag.Parse()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.Fatal("GOOGLE_CLOUD_PROJECT environment variable is not set")
	}

	config := ImporterConfig{
		StrictValidation: *strictValidation,
		NumWorkers:       *numWorkers,
		GitWorkDir:       filepath.Join(*workDir, "sources"),
	}

	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = 3
	httpClient.RetryWaitMin = 1 * time.Second
	httpClient.RetryWaitMax = 4 * time.Second
	httpClient.Logger = retryableHTTPLeveledLogger{}
	config.HTTPClient = httpClient.StandardClient()

	datastoreClient, err := datastore.NewClient(context.Background(), project)
	if err != nil {
		logger.Fatal("Failed to create datastore client", slog.Any("error", err))
	}
	config.SourceRepoStore = db.NewSourceRepositoryStore(datastoreClient)

	psClient, err := pubsub.NewClient(context.Background(), project)
	if err != nil {
		logger.Fatal("Failed to create pubsub client", slog.Any("error", err))
	}
	config.Publisher = psClient.Publisher(tasksTopic)

	config.GCSClient, err = storage.NewClient(context.Background())
	if err != nil {
		logger.Fatal("Failed to create GCS client", slog.Any("error", err))
	}

	if *delete {
		_ = deleteThresholdPct
		logger.Fatal("delete not implemented yet")
	}

	if err := RunImporter(context.Background(), config); err != nil {
		logger.Fatal("Importer failed", slog.Any("error", err))
	}
}

func RunImporter(ctx context.Context, config ImporterConfig) error {
	logger.Info("Importer started")

	workCh := make(chan SourceRecord)
	var workWg sync.WaitGroup
	for range config.NumWorkers {
		workWg.Go(func() {
			ImporterWorker(ctx, workCh, config)
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

func ImporterWorker(ctx context.Context, ch <-chan SourceRecord, config ImporterConfig) {
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
			}
			defer r.Close()
			data, err := io.ReadAll(r)
			if err != nil {
				logger.Error("Failed to read source record",
					slog.Any("error", err),
					slog.String("source_repository", sourceRepoName),
					slog.String("source_path", sourceRecord.SourcePath()))
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

func sendToWorker(ctx context.Context, config ImporterConfig, sourceRecord SourceRecord, hash string, modifiedTime time.Time) error {
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
