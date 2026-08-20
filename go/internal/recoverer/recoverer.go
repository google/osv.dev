// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package recoverer implements the OSV failed task recoverer.
package recoverer

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/gitter"
	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type Stores struct {
	DatastoreClient *datastore.Client
	SourceRepo      models.SourceRepositoryStore
	Relations       models.RelationsStore
	GCS             clients.CloudStorage
	GCSProvider     clients.CloudStorageProvider
	Publisher       clients.Publisher
}

type Config struct {
	Stores           Stores
	GitterClient     gitter.Client
	HTTPClient       *http.Client
	DefaultTaskPool  string
	ReimportTaskPool string
}

type Recoverer struct {
	stores           Stores
	gitterClient     gitter.Client
	httpClient       *http.Client
	defaultTaskPool  string
	reimportTaskPool string
}

func New(cfg Config) *Recoverer {
	defaultPool := cfg.DefaultTaskPool
	if defaultPool == "" {
		defaultPool = "default"
	}
	reimportPool := cfg.ReimportTaskPool
	if reimportPool == "" {
		reimportPool = "reimport"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Recoverer{
		stores:           cfg.Stores,
		gitterClient:     cfg.GitterClient,
		httpClient:       httpClient,
		defaultTaskPool:  defaultPool,
		reimportTaskPool: reimportPool,
	}
}

// Run starts the subscriber loop listening for recovery tasks.
func (r *Recoverer) Run(ctx context.Context, sub *pubsub.Subscriber) error {
	return sub.Receive(ctx, r.HandleMessage)
}

// HandleMessage handles a single Pub/Sub message from the failed tasks subscription.
func (r *Recoverer) HandleMessage(ctx context.Context, m *pubsub.Message) {
	taskType := m.Attributes["type"]
	logInfo := []any{
		slog.String("type", taskType),
		slog.String("id", m.Attributes["id"]),
	}

	taskCtx := otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier(m.Attributes))
	taskCtx, span := otel.Tracer("recoverer").Start(taskCtx, "process_task",
		trace.WithAttributes(attribute.String("task_type", taskType)))
	defer span.End()

	var err error
	switch taskType {
	case "gcs_retry":
		err = r.HandleGCSRetry(taskCtx, m)
	case "gcs_missing":
		err = r.HandleGCSMissing(taskCtx, m)
	case "gcs_gen_mismatch":
		err = r.HandleGCSGenMismatch(taskCtx, m)
	default:
		err = r.HandleGeneric(taskCtx, m)
	}

	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to process recovery task", append(logInfo, slog.Any("error", err))...)
		m.Nack()
	} else {
		m.Ack()
	}
}

// HandleGCSRetry handles a failed GCS write.
func (r *Recoverer) HandleGCSRetry(ctx context.Context, m *pubsub.Message) error {
	var vuln osvschema.Vulnerability
	if err := proto.Unmarshal(m.Data, &vuln); err != nil {
		logger.ErrorContext(ctx, "gcs_retry: failed to decode protobuf. Ignoring message.",
			slog.Any("error", err),
			slog.String("data_base64", base64.StdEncoding.EncodeToString(m.Data)))
		// Non-retryable decoding error, return nil to ack
		return nil
	}

	vulnID := vuln.GetId()
	logger.InfoContext(ctx, "gcs_retry: vulnerability", slog.String("id", vulnID))
	modified := vuln.GetModified().AsTime()
	path := fmt.Sprintf("all/pb/%s.pb", vulnID)

	attrs, err := r.stores.GCS.ReadObjectAttrs(ctx, path)
	if err == nil {
		if !attrs.CustomTime.IsZero() && (attrs.CustomTime.Equal(modified) || attrs.CustomTime.After(modified)) {
			logger.WarnContext(ctx, "gcs_retry: was modified before message was processed",
				slog.String("id", vulnID),
				slog.Time("message_modified", modified),
				slog.Time("blob_modified", attrs.CustomTime))

			return nil
		}
	} else if !errors.Is(err, clients.ErrNotFound) {
		logger.ErrorContext(ctx, "gcs_retry: failed to get object attrs from GCS", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}

	opts := &clients.WriteOptions{
		CustomTime:  &modified,
		ContentType: "application/octet-stream",
	}
	if err := r.stores.GCS.WriteObject(ctx, path, m.Data, opts); err != nil {
		logger.ErrorContext(ctx, "gcs_retry: failed to upload protobuf to GCS", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}

	return nil
}

// HandleGCSMissing handles a failed GCS read by triggering a reimport.
func (r *Recoverer) HandleGCSMissing(ctx context.Context, m *pubsub.Message) error {
	vulnID := m.Attributes["id"]
	logger.InfoContext(ctx, "gcs_missing: vulnerability", slog.String("id", vulnID))
	if vulnID == "" {
		logger.ErrorContext(ctx, "gcs_missing: message missing id attribute")

		return nil
	}

	var vuln osvdatastore.Vulnerability
	key := datastore.NameKey("Vulnerability", vulnID, nil)
	if err := r.stores.DatastoreClient.Get(ctx, key, &vuln); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			logger.ErrorContext(ctx, "gcs_missing: Vulnerability entity not found", slog.String("id", vulnID))

			return nil
		}
		logger.ErrorContext(ctx, "gcs_missing: failed to fetch Vulnerability entity", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}

	source, path, ok := strings.Cut(vuln.SourceID, ":")
	if !ok || source == "" || path == "" {
		logger.ErrorContext(ctx, "gcs_missing: invalid source_id", slog.String("id", vulnID), slog.String("source_id", vuln.SourceID))

		return nil
	}

	logger.InfoContext(ctx, "gcs_missing: triggering re-import", slog.String("id", vulnID), slog.String("source_id", vuln.SourceID))

	data, err := r.DownloadVulnData(ctx, source, path)
	if err != nil {
		logger.ErrorContext(ctx, "gcs_missing: failed to download vuln data", slog.String("id", vulnID), slog.String("source_id", vuln.SourceID), slog.Any("error", err))

		return err
	}

	msg := &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"type":             "update",
			"source":           source,
			"path":             path,
			"original_sha256":  "",
			"deleted":          "false",
			"skip_hash_check":  "true",
			"req_timestamp":    strconv.FormatInt(time.Now().Unix(), 10),
			"content_encoding": "",
			"work_pool":        r.reimportTaskPool,
		},
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(msg.Attributes))

	res := r.stores.Publisher.Publish(ctx, msg)
	if _, err := res.Get(ctx); err != nil {
		logger.ErrorContext(ctx, "gcs_missing: failed to publish update message", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}

	return nil
}

// DownloadVulnData downloads and parses vulnerability data from the source repository.
func (r *Recoverer) DownloadVulnData(ctx context.Context, source, vulnPath string) ([]byte, error) {
	sourceRepo, err := r.stores.SourceRepo.Get(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("failed to get source repository %s: %w", source, err)
	}

	var rawData []byte
	switch sourceRepo.Type {
	case models.SourceRepositoryTypeREST:
		if sourceRepo.Link == "" {
			return nil, fmt.Errorf("REST source repository %s is missing Link", source)
		}
		reqURL, err := url.JoinPath(sourceRepo.Link, vulnPath)
		if err != nil {
			return nil, fmt.Errorf("failed to construct REST URL for %s / %s: %w", sourceRepo.Link, vulnPath, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		resp, err := r.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request failed for %s: %w", reqURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP request failed with status %d for %s", resp.StatusCode, reqURL)
		}
		rawData, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body for %s: %w", reqURL, err)
		}

	case models.SourceRepositoryTypeBucket:
		if sourceRepo.Bucket == nil || sourceRepo.Bucket.Name == "" {
			return nil, fmt.Errorf("bucket source repository %s is missing bucket name", source)
		}
		if r.stores.GCSProvider == nil {
			return nil, errors.New("GCSProvider is not configured")
		}
		bucketStorage := r.stores.GCSProvider.Bucket(sourceRepo.Bucket.Name)
		rawData, err = bucketStorage.ReadObject(ctx, vulnPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read object %s from bucket %s: %w", vulnPath, sourceRepo.Bucket.Name, err)
		}

	case models.SourceRepositoryTypeGit:
		if sourceRepo.Git == nil || sourceRepo.Git.URL == "" {
			return nil, fmt.Errorf("git source repository %s is missing git url", source)
		}
		if r.gitterClient == nil {
			return nil, errors.New("gitter client is not configured")
		}
		ref := sourceRepo.Git.LastSyncedCommit
		if ref == "" {
			ref = sourceRepo.Git.Branch
		}
		if ref == "" {
			ref = "HEAD"
		}
		req := &gitterpb.FileContentRequest{
			Url:    sourceRepo.Git.URL,
			Commit: ref,
			Path:   vulnPath,
		}
		resp, err := r.gitterClient.GetFileContent(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("gitter GetFileContent failed for %s (commit %s, path %s): %w", sourceRepo.Git.URL, ref, vulnPath, err)
		}
		rawData = resp.GetContent()

	default:
		return nil, fmt.Errorf("unhandled source repository type: %v", sourceRepo.Type)
	}

	vulnProto, err := parseVulnerability(rawData, sourceRepo.Extension, vulnPath, sourceRepo.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability data for %s:%s: %w", source, vulnPath, err)
	}

	return proto.Marshal(vulnProto)
}

func parseVulnerability(raw []byte, extension, vulnPath, keyPath string) (*osvschema.Vulnerability, error) {
	data := bytes.ToValidUTF8(raw, []byte("\uFFFD"))
	ext := strings.ToLower(extension)
	if ext == ".yaml" || ext == ".yml" || strings.HasSuffix(strings.ToLower(vulnPath), ".yaml") || strings.HasSuffix(strings.ToLower(vulnPath), ".yml") {
		jsonBytes, err := yaml.ToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
		}
		data = jsonBytes
	}

	if keyPath != "" {
		res := gjson.GetBytes(data, keyPath)
		if !res.Exists() {
			return nil, fmt.Errorf("key path %q not found in data", keyPath)
		}
		data = []byte(res.Raw)
	}

	var vulnProto osvschema.Vulnerability
	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshalOptions.Unmarshal(data, &vulnProto); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OSV proto: %w", err)
	}

	return &vulnProto, nil
}

// HandleGCSGenMismatch handles a generation mismatch when attempting to update a part of a record.
func (r *Recoverer) HandleGCSGenMismatch(ctx context.Context, m *pubsub.Message) error {
	vulnID := m.Attributes["id"]
	fieldStr := m.Attributes["field"]
	logger.InfoContext(ctx, "gcs_gen_mismatch: vulnerability", slog.String("id", vulnID), slog.String("field", fieldStr))
	if vulnID == "" || fieldStr == "" {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: message missing id or field attribute")

		return nil
	}

	path := fmt.Sprintf("all/pb/%s.pb", vulnID)
	attrs, err := r.stores.GCS.ReadObjectAttrs(ctx, path)
	if errors.Is(err, clients.ErrNotFound) {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: vulnerability not in GCS", slog.String("id", vulnID))
		logger.InfoContext(ctx, "trying with gcs_missing", slog.String("id", vulnID))

		return r.HandleGCSMissing(ctx, m)
	}
	if err != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: failed to read object attrs from GCS", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}
	generation := attrs.Generation

	data, err := r.stores.GCS.ReadObject(ctx, path)
	if err != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: failed to read object data from GCS", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}

	var baseProto osvschema.Vulnerability
	if err := proto.Unmarshal(data, &baseProto); err != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: failed to unmarshal proto from GCS", slog.String("id", vulnID), slog.Any("error", err))

		return nil
	}

	var modified time.Time
	var finalProto *osvschema.Vulnerability
	vulnKey := datastore.NameKey("Vulnerability", vulnID, nil)
	dsFound := true

	_, txErr := r.stores.DatastoreClient.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var dsVuln osvdatastore.Vulnerability
		if err := tx.Get(vulnKey, &dsVuln); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				logger.ErrorContext(ctx, "vulnerability not in Datastore", slog.String("id", vulnID))
				dsFound = false

				return nil
			}

			return err
		}
		modified = dsVuln.Modified
		vulnProto := proto.Clone(&baseProto).(*osvschema.Vulnerability)

		fields := strings.Split(fieldStr, ",")
		for _, f := range fields {
			switch strings.TrimSpace(f) {
			case "aliases":
				aliasResult, err := r.stores.Relations.GetAliases(ctx, vulnID)
				var aliases []string
				var aliasesModified time.Time
				if errors.Is(err, models.ErrNotFound) {
					aliases = []string{}
					aliasesModified = time.Now().UTC()
				} else if err != nil {
					return fmt.Errorf("failed to get aliases for %s: %w", vulnID, err)
				} else {
					aliases = aliasResult.Aliases
					aliasesModified = aliasResult.Modified
				}
				if !slices.Equal(vulnProto.GetAliases(), aliases) {
					vulnProto.Aliases = aliases
					if aliasesModified.After(modified) {
						modified = aliasesModified
					} else {
						modified = time.Now().UTC()
					}
				}

			case "upstream":
				upstreamResult, err := r.stores.Relations.GetUpstream(ctx, vulnID)
				var upstream []string
				var upstreamModified time.Time
				if errors.Is(err, models.ErrNotFound) {
					upstream = []string{}
					upstreamModified = time.Now().UTC()
				} else if err != nil {
					return fmt.Errorf("failed to get upstream for %s: %w", vulnID, err)
				} else {
					upstream = upstreamResult.Upstream
					upstreamModified = upstreamResult.Modified
				}
				if !slices.Equal(vulnProto.GetUpstream(), upstream) {
					vulnProto.Upstream = upstream
					if upstreamModified.After(modified) {
						modified = upstreamModified
					} else {
						modified = time.Now().UTC()
					}
				}

			case "related":
				relatedResult, err := r.stores.Relations.GetRelated(ctx, vulnID)
				var related []string
				var relatedModified time.Time
				if errors.Is(err, models.ErrNotFound) {
					related = []string{}
					relatedModified = time.Now().UTC()
				} else if err != nil {
					return fmt.Errorf("failed to get related for %s: %w", vulnID, err)
				} else {
					related = relatedResult.Related
					relatedModified = relatedResult.Modified
				}
				if !slices.Equal(vulnProto.GetRelated(), related) {
					vulnProto.Related = related
					if relatedModified.After(modified) {
						modified = relatedModified
					} else {
						modified = time.Now().UTC()
					}
				}
			}
		}

		vulnProto.Modified = timestamppb.New(modified)
		dsVuln.Modified = modified
		listedVuln := osvdatastore.NewListedVulnerabilityFromProto(vulnProto)
		listedKey := datastore.NameKey("ListedVulnerability", vulnID, nil)

		if _, err := tx.Put(vulnKey, &dsVuln); err != nil {
			return err
		}
		if _, err := tx.Put(listedKey, listedVuln); err != nil {
			return err
		}

		finalProto = vulnProto

		return nil
	})

	if txErr != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: Datastore transaction failed",
			slog.String("id", vulnID), slog.String("field", fieldStr), slog.Any("error", txErr))

		return txErr
	}

	if !dsFound {
		return nil
	}

	newData, err := proto.Marshal(finalProto)
	if err != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: failed to marshal proto", slog.String("id", vulnID), slog.Any("error", err))

		return err
	}
	opts := &clients.WriteOptions{
		IfGenerationMatches: &generation,
		CustomTime:          &modified,
		ContentType:         "application/octet-stream",
	}
	if err := r.stores.GCS.WriteObject(ctx, path, newData, opts); err != nil {
		logger.ErrorContext(ctx, "gcs_gen_mismatch: Writing to bucket failed",
			slog.String("id", vulnID), slog.String("field", fieldStr), slog.Any("error", err))

		return err
	}

	return nil
}

// HandleGeneric handles unhandled task types by logging and acknowledging.
func (r *Recoverer) HandleGeneric(ctx context.Context, m *pubsub.Message) error {
	taskType := m.Attributes["type"]
	if taskType == "" {
		taskType = "unknown"
	}
	logger.ErrorContext(ctx, fmt.Sprintf("`%s` task could not be processed", taskType),
		slog.String("type", taskType),
		slog.Any("attributes", m.Attributes))

	return nil
}
