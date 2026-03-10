// Package importer provides functionality for importing vulnerability records from various sources.
package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
	SampleRate       float64
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
	logger.InfoContext(ctx, "Importer started")

	workCh := make(chan WorkItem)
	var workWg sync.WaitGroup
	for range config.NumWorkers {
		workWg.Go(func() {
			importerWorker(ctx, workCh, config)
		})
	}

	var sourceWg sync.WaitGroup
	for sourceRepo, err := range config.SourceRepoStore.All(ctx) {
		if err != nil {
			return err
		}
		//nolint:dupl // Some duplication here is fine
		sourceWg.Go(func() {
			ctx, span := otel.Tracer("importer").Start(ctx, sourceRepo.Name)
			defer span.End()
			switch sourceRepo.Type {
			case models.SourceRepositoryTypeGit:
				if err := handleImportGit(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to import git source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeBucket:
				if err := handleImportBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to import bucket source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleImportREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to import REST source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			default:
				logger.ErrorContext(ctx, "Unsupported source repository type", slog.String("source", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
			}
		})
	}
	sourceWg.Wait()
	close(workCh)
	workWg.Wait()

	return nil
}

func RunDeletions(ctx context.Context, config Config) error {
	logger.InfoContext(ctx, "Deletion reconciler started")

	workCh := make(chan WorkItem)
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
			ctx, span := otel.Tracer("importer").Start(ctx, sourceRepo.Name)
			defer span.End()
			switch sourceRepo.Type {
			case models.SourceRepositoryTypeGit:
				// Git deletions are handled in regular importer
				return
			case models.SourceRepositoryTypeBucket:
				if err := handleDeleteBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to process bucket deletions", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleDeleteREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to process REST deletions", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			default:
				logger.ErrorContext(ctx, "Unsupported source repository type for deletions", slog.String("source", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
			}
		})
	}
	wg.Wait()
	close(workCh)
	workWg.Wait()

	return nil
}

// reconcileSkipSources is a list of source names to skip during reconciliation.
var reconcileSkipSources = []string{
	// Upstream records are completely deprecated and archived now.
	"uvi",
	// Currently an upstream issue that we can't fix.
	"almalinux-alsa",

	// "oss-fuzz",
	// "debian-cve",
	// "cve-osv",
}

// ReconcileLeniencyDuration specifies how long of a time difference before it would be considered an outdated record
// This needs to be some time as importer detecting the change to worker importing it is not instant.
const ReconcileLeniencyDuration = time.Hour * 6

func RunReconcile(ctx context.Context, config Config) error {
	logger.InfoContext(ctx, "Reconciler started")

	workCh := make(chan WorkItem)
	var workWg sync.WaitGroup
	for range config.NumWorkers {
		workWg.Go(func() {
			importerWorker(ctx, workCh, config)
		})
	}

	var wg sync.WaitGroup
	//nolint:prealloc // Size is unknown since All() returns an iterator
	var sourceRepos []*models.SourceRepository
	gitBranches := make(map[string]string) // url -> branch

	for sourceRepo, err := range config.SourceRepoStore.All(ctx) {
		if err != nil {
			return err
		}

		// Sanity check for multiple sources with same git url but different branches.
		// This is not currently supported.
		if sourceRepo.Type == models.SourceRepositoryTypeGit && sourceRepo.Git != nil {
			if existingBranch, ok := gitBranches[sourceRepo.Git.URL]; ok {
				if existingBranch != sourceRepo.Git.Branch {
					return fmt.Errorf("multiple sources with same git url %q but different branches (%q and %q) is not supported",
						sourceRepo.Git.URL, existingBranch, sourceRepo.Git.Branch)
				}
			} else {
				gitBranches[sourceRepo.Git.URL] = sourceRepo.Git.Branch
			}
		}

		sourceRepos = append(sourceRepos, sourceRepo)
	}

	for _, sr := range sourceRepos {
		sourceRepo := sr // capture loop variable cleanly

		if slices.Contains(reconcileSkipSources, sourceRepo.Name) {
			logger.InfoContext(ctx, "Skipping reconciliation for source", slog.String("source", sourceRepo.Name))
			continue
		}
		//nolint:dupl // Some duplication here is fine
		wg.Go(func() {
			ctx, span := otel.Tracer("importer").Start(ctx, sourceRepo.Name)
			defer span.End()
			switch sourceRepo.Type {
			case models.SourceRepositoryTypeGit:
				if err := handleReconcileGit(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to reconcile git source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeBucket:
				if err := handleReconcileBucket(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to reconcile bucket source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			case models.SourceRepositoryTypeREST:
				if err := handleReconcileREST(ctx, workCh, config, sourceRepo); err != nil {
					logger.ErrorContext(ctx, "Failed to reconcile REST source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
				}
			default:
				logger.ErrorContext(ctx, "Unsupported source repository type for reconciliation", slog.String("source", sourceRepo.Name), slog.Any("type", sourceRepo.Type))
			}
		})
	}
	wg.Wait()
	close(workCh)
	workWg.Wait()

	return nil
}

// fetchDBRecords retrieves the modified dates for all vulnerability records associated with a given source repository.
//
// Arguments:
//   - ctx: Context used for datastore queries.
//   - config: Configuration containing the VulnerabilityStore.
//   - sourceRepo: The SourceRepository configuration to fetch existing records for.
func fetchDBRecords(ctx context.Context, config Config, sourceRepo *models.SourceRepository) (map[string]time.Time, error) {
	dbRecords := make(map[string]time.Time)
	for entry, err := range config.VulnerabilityStore.ListBySource(ctx, sourceRepo.Name, false) {
		if err != nil {
			return nil, err
		}
		dbRecords[entry.Path] = entry.ModifiedRaw
	}

	return dbRecords, nil
}

// checkReconcile checks the upstream modified date against the datastore and triggers a reimport if necessary.
// It constructs the WorkItem template and manages the logic entirely.
//
// Arguments:
//   - ctx: Processing context.
//   - ch: Channel to push the WorkItem to for re-importing.
//   - sourceRepo: The configuration of the repository being imported.
//   - dbRecords: A map containing the datastore 'modified_raw' timestamps for this source.
//   - path: The relative path or ID representing this specific vulnerability record upstream.
//   - parsed: A pointer to a pre-parsed gjson.Result if already available. If nil, sourceRecord is opened and parsed dynamically.
//   - sourceRecord: The interface used to lazily retrieve file contents (from a bucket, git, or REST).
//   - format: RecordFormat representing the format we expect to decode (JSON, YAML, etc.).
func checkReconcile(
	ctx context.Context,
	ch chan<- WorkItem,
	sourceRepo *models.SourceRepository,
	dbRecords map[string]time.Time,
	path string,
	parsed *gjson.Result,
	sourceRecord SourceRecord,
	format RecordFormat,
) {
	recordTemplate := WorkItem{
		Context:          ctx,
		SourceRecord:     sourceRecord,
		SourceRepository: sourceRepo.Name,
		SourcePath:       path,
		Format:           format,
		KeyPath:          sourceRepo.KeyPath,
		Strict:           sourceRepo.Strictness,
		IsReimport:       true,
	}

	dbMod, exists := dbRecords[path]
	if !exists {
		logger.ErrorContext(ctx, "Found missing vulnerability in datastore during reconcile",
			slog.String("source", recordTemplate.SourceRepository),
			slog.String("path", path))
		// panic("Found missing vulnerability in datastore during reconcile")
		ch <- recordTemplate

		return
	}

	var parsedToUse gjson.Result
	if parsed != nil {
		parsedToUse = *parsed
	} else {
		r, err := sourceRecord.Open(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to open source record during reconcile",
				slog.Any("error", err),
				slog.String("source", recordTemplate.SourceRepository),
				slog.String("path", path))

			return
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			logger.ErrorContext(ctx, "Failed to read source record during reconcile",
				slog.Any("error", err),
				slog.String("source", recordTemplate.SourceRepository),
				slog.String("path", path))

			return
		}

		if format == RecordFormatYAML {
			json, err := yaml.ToJSON(data)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to convert YAML to JSON in reconcile",
					slog.Any("error", err),
					slog.String("source", recordTemplate.SourceRepository),
					slog.String("path", path))

				return
			}
			data = json
		}

		if keyPath := sourceRepo.KeyPath; keyPath != "" {
			res := gjson.GetBytes(data, keyPath)
			if !res.Exists() {
				logger.ErrorContext(ctx, "Key path not found in reconcile",
					slog.String("key_path", keyPath),
					slog.String("source", recordTemplate.SourceRepository),
					slog.String("path", path))

				return
			}
			data = []byte(res.Raw)
		}

		parsedToUse = gjson.ParseBytes(data)
	}

	if !parsedToUse.Get("id").Exists() {
		logger.ErrorContext(ctx, "Vulnerability missing id in reconcile",
			slog.String("source", recordTemplate.SourceRepository),
			slog.String("path", path))

		return
	}

	modifiedObj := parsedToUse.Get("modified")
	if !modifiedObj.Exists() {
		logger.WarnContext(ctx, "Vulnerability missing modified in reconcile",
			slog.String("source", recordTemplate.SourceRepository),
			slog.String("path", path))

		return
	}

	modified, err := time.Parse(time.RFC3339, modifiedObj.String())
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse modified in reconcile",
			slog.Any("error", err),
			slog.String("source", recordTemplate.SourceRepository),
			slog.String("path", path))

		return
	}

	if modified.After(dbMod.Add(ReconcileLeniencyDuration)) {
		logger.ErrorContext(ctx, "Found outdated vulnerability in datastore during reconcile",
			slog.String("source", recordTemplate.SourceRepository),
			slog.String("path", path),
			slog.Time("datastore_modified", dbMod),
			slog.Time("upstream_modified", modified))
		ch <- recordTemplate
	}
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
}

type WorkItem struct {
	// Context is included to propagate tracing spans (links) and cancellation
	// across the worker pool. This is a pragmatic choice for batch job processing.
	Context      context.Context //nolint:containedctx
	SourceRecord SourceRecord

	SourceRepository string
	SourcePath       string
	Format           RecordFormat
	KeyPath          string
	Strict           bool
	IsDeleted        bool
	LastUpdated      time.Time
	HasLastUpdated   bool
	IsReimport       bool
}

func importerWorker(ctx context.Context, ch <-chan WorkItem, config Config) {
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-ch:
			if !ok {
				return
			}
			// wrap in function so defer is called for each item
			func() { //nolint:contextcheck
				// create a new span for the vulnerability,
				// not part of the importer span, but linked to it.
				// This way, we can sample vuln updates separately
				// and trace it all the way through to the worker.
				link := trace.LinkFromContext(item.Context)
				ctx, span := otel.Tracer("update").Start(item.Context, item.SourcePath,
					trace.WithNewRoot(), trace.WithLinks(link),
					trace.WithAttributes(attribute.Float64("override_sample_rate", config.SampleRate)))
				defer span.End()

				if item.IsDeleted {
					if err := sendDeletionToWorker(ctx, config, item); err != nil {
						logger.ErrorContext(ctx, "Failed to send deletion to worker",
							slog.Any("error", err),
							slog.String("source", item.SourceRepository),
							slog.String("path", item.SourcePath))
					}

					return
				}
				processUpdate(ctx, config, item)
			}()
		}
	}
}

func processUpdate(ctx context.Context, config Config, item WorkItem) {
	sourceRecord := item.SourceRecord
	sourceRepoName := item.SourceRepository
	sourcePath := item.SourcePath
	strict := config.StrictValidation && item.Strict

	unmarshalOptions := protojson.UnmarshalOptions{
		DiscardUnknown: !strict,
	}
	r, err := sourceRecord.Open(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to open source record",
			slog.Any("error", err),
			slog.String("source", sourceRepoName),
			slog.String("path", sourcePath))

		return
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read source record",
			slog.Any("error", err),
			slog.String("source", sourceRepoName),
			slog.String("path", sourcePath))

		return
	}
	hash := computeHash(data)
	var vulnProto osvschema.Vulnerability
	switch item.Format {
	case RecordFormatYAML:
		// convert YAML to JSON, then use JSON logic below
		json, err := yaml.ToJSON(data)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert YAML to JSON",
				slog.Any("error", err),
				slog.String("source", sourceRepoName),
				slog.String("path", sourcePath))

			return
		}
		data = json

		fallthrough
	case RecordFormatJSON:
		// unmarshal JSON to proto
		if keyPath := item.KeyPath; keyPath != "" {
			res := gjson.GetBytes(data, keyPath)
			if !res.Exists() {
				logger.ErrorContext(ctx, "Key path not found",
					slog.String("key_path", keyPath),
					slog.String("source", sourceRepoName),
					slog.String("path", sourcePath))

				return
			}
			data = []byte(res.Raw)
		}

		if strict {
			if err := Validate(data); err != nil {
				logger.ErrorContext(ctx, "JSON schema validation failed",
					slog.Any("error", err),
					slog.String("source", sourceRepoName),
					slog.String("path", sourcePath))

				return
			}
		}

		if err := unmarshalOptions.Unmarshal(data, &vulnProto); err != nil {
			logger.ErrorContext(ctx, "Failed to unmarshal OSV proto",
				slog.Any("error", err),
				slog.String("source", sourceRepoName),
				slog.String("path", sourcePath))

			return
		}
	default:
		logger.ErrorContext(ctx, "Unknown record format",
			slog.String("source", sourceRepoName),
			slog.String("path", sourcePath))

		return
	}
	// Skip if the record is older than the last update time
	modified := vulnProto.GetModified().AsTime()
	if item.HasLastUpdated {
		if item.LastUpdated.After(modified) {
			return
		}
	}
	if err := sendToWorker(ctx, config, item, hash, modified, &vulnProto); err != nil {
		logger.ErrorContext(ctx, "Failed to send to worker",
			slog.Any("error", err),
			slog.String("source", sourceRepoName),
			slog.String("path", sourcePath),
			slog.String("id", vulnProto.GetId()))

		return
	}
	logger.InfoContext(ctx, "Sent to worker",
		slog.String("source", sourceRepoName),
		slog.String("path", sourcePath),
		slog.String("id", vulnProto.GetId()))
}

func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func sendToWorker(ctx context.Context, config Config, item WorkItem, hash string, modifiedTime time.Time, vuln *osvschema.Vulnerability) error {
	var srcTimestamp *time.Time
	if !item.IsReimport {
		// Only track the update latency if we're not doing a reimport of the data
		srcTimestamp = &modifiedTime
	}

	return publishUpdate(ctx, config.Publisher, item.SourceRepository, item.SourcePath, hash, false, srcTimestamp, vuln)
}

func sendDeletionToWorker(ctx context.Context, config Config, item WorkItem) error {
	return publishUpdate(ctx, config.Publisher, item.SourceRepository, item.SourcePath, "", true, nil, nil)
}

func publishUpdate(ctx context.Context, publisher clients.Publisher, source, path, hash string, deleted bool, srcTimestamp *time.Time, vuln *osvschema.Vulnerability) error {
	// Send the vulnerability proto in the message data
	var data []byte
	if vuln != nil {
		var err error
		data, err = proto.Marshal(vuln)
		if err != nil {
			return err
		}
	}
	msg := &pubsub.Message{
		Data: data,
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
	// Inject the current trace into the message
	otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(msg.Attributes))

	result := publisher.Publish(ctx, msg)
	_, err := result.Get(ctx)

	return err
}
