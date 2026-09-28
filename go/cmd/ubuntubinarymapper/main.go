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

// Package main implements the ubuntubinarymapper service that discovers Ubuntu
// vulnerability records from the exported GCS bucket, extracts binary-to-source
// package name mappings, and saves them to Datastore or a local JSON store.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/database/jsonstore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	jobDataKind           = "JobData"
	jobDataLastRunKey     = "ubuntu_binary_mapper_last_run"
	defaultBucketName     = "osv-vulnerabilities"
	ubuntuPrefix          = "Ubuntu"
	ubuntuModifiedCSVPath = "Ubuntu/modified_id.csv"
	ubuntuAllZipPath      = "Ubuntu/all.zip"
	zipDownloadThreshold  = 1000
	defaultNumWorkers     = 20
	lookbackWindow        = time.Hour
)

type jobDataEntity struct {
	Value time.Time `datastore:"value,noindex"`
}

func getLastRunFromDatastore(ctx context.Context, dsClient *datastore.Client) (time.Time, error) {
	key := datastore.NameKey(jobDataKind, jobDataLastRunKey, nil)
	var e jobDataEntity
	if err := dsClient.Get(ctx, key, &e); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return time.Time{}, nil
		}

		return time.Time{}, fmt.Errorf("failed to get JobData for %q: %w", jobDataLastRunKey, err)
	}

	return e.Value, nil
}

func setLastRunInDatastore(ctx context.Context, dsClient *datastore.Client, t time.Time) error {
	key := datastore.NameKey(jobDataKind, jobDataLastRunKey, nil)
	if _, err := dsClient.Put(ctx, key, &jobDataEntity{Value: t.UTC()}); err != nil {
		return fmt.Errorf("failed to put JobData for %q: %w", jobDataLastRunKey, err)
	}

	return nil
}

// findModifiedUbuntuIDs reads Ubuntu/modified_id.csv from the GCS bucket and returns all
// vulnerability IDs modified after lastRun minus a 1-hour lookback window
// (if lastRun is zero, all IDs in the CSV are returned).
func findModifiedUbuntuIDs(ctx context.Context, gcsStorage clients.CloudStorage, lastRun time.Time) ([]string, error) {
	csvBytes, err := gcsStorage.ReadObject(ctx, ubuntuModifiedCSVPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %w", ubuntuModifiedCSVPath, err)
	}

	var cutoff time.Time
	if !lastRun.IsZero() {
		cutoff = lastRun.Add(-lookbackWindow)
	}

	var ids []string
	scanner := bufio.NewScanner(bytes.NewReader(csvBytes))
	for scanner.Scan() {
		tsStr, id, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ",")
		if !ok || id == "" {
			continue
		}
		modTime, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			logger.WarnContext(ctx, "invalid timestamp in modified_id.csv", slog.String("ts", tsStr), slog.Any("err", err))
			continue
		}
		// Ubuntu/modified_id.csv is sorted by modified date descending.
		if !modTime.After(cutoff) {
			break
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning %s: %w", ubuntuModifiedCSVPath, err)
	}

	return ids, nil
}

// ExtractBinaryMappings extracts a map of binary_name -> slice of source_names from a Vulnerability record.
func ExtractBinaryMappings(vuln *osvschema.Vulnerability) map[string][]string {
	mappings := make(map[string][]string)
	for _, affected := range vuln.GetAffected() {
		sourceName := affected.GetPackage().GetName()
		if sourceName == "" {
			continue
		}

		binaries := affected.GetEcosystemSpecific().GetFields()["binaries"].GetListValue().GetValues()
		for _, item := range binaries {
			binName := strings.TrimSpace(item.GetStructValue().GetFields()["binary_name"].GetStringValue())
			if binName != "" {
				mappings[binName] = append(mappings[binName], sourceName)
			}
		}
	}

	return mappings
}

// appEnv holds configured services and dependencies.
type appEnv struct {
	gcsStorage   clients.CloudStorage
	ubuntuStore  models.UbuntuPackageMappingStore
	dsClient     *datastore.Client
	lastRun      time.Time
	numWorkers   int
	zipThreshold int
	closer       func()
}

func setup(ctx context.Context) (*appEnv, error) {
	outputJSON := flag.String("output-json", "", "Path to local JSON file for writing/storing mappings (enables local mode, bypassing Datastore)")
	lastRunFlag := flag.String("last-run", "", "Last job run time in RFC3339 format (used in local mode when -output-json is set)")
	bucketName := flag.String("bucket", cmp.Or(os.Getenv("OSV_VULNERABILITIES_BUCKET"), defaultBucketName), "GCS bucket name containing exported OSV vulnerabilities")
	projectID := flag.String("project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "Google Cloud project ID")
	datastoreID := flag.String("datastore-id", os.Getenv("DATASTORE_DATABASE_ID"), "Datastore database ID")
	numWorkers := flag.Int("num-workers", defaultNumWorkers, "Number of worker goroutines")
	flag.Parse()

	storageClient, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	gcsStorage := clients.NewGCSClient(storageClient, *bucketName)

	// Local mode when -output-json is provided
	if *outputJSON != "" {
		var lastRun time.Time
		if *lastRunFlag != "" {
			lastRun, err = time.Parse(time.RFC3339Nano, *lastRunFlag)
			if err != nil {
				storageClient.Close()

				return nil, fmt.Errorf("invalid -last-run timestamp %q (expected RFC3339): %w", *lastRunFlag, err)
			}
			lastRun = lastRun.UTC()
		}

		jsonStore, err := jsonstore.New(*outputJSON)
		if err != nil {
			storageClient.Close()

			return nil, fmt.Errorf("failed creating JSON store %s: %w", *outputJSON, err)
		}

		return &appEnv{
			gcsStorage:   gcsStorage,
			ubuntuStore:  jsonStore,
			lastRun:      lastRun,
			numWorkers:   *numWorkers,
			zipThreshold: zipDownloadThreshold,
			closer:       func() { storageClient.Close() },
		}, nil
	}

	// Production Datastore/GCS mode
	if *projectID == "" {
		storageClient.Close()

		return nil, errors.New("GOOGLE_CLOUD_PROJECT or -project must be set when not running with -output-json")
	}

	dsClient, err := datastore.NewClientWithDatabase(ctx, *projectID, *datastoreID)
	if err != nil {
		storageClient.Close()

		return nil, fmt.Errorf("failed to create datastore client: %w", err)
	}

	lastRun, err := getLastRunFromDatastore(ctx, dsClient)
	if err != nil {
		dsClient.Close()
		storageClient.Close()

		return nil, err
	}

	return &appEnv{
		gcsStorage:   gcsStorage,
		ubuntuStore:  db.NewUbuntuPackageMappingStore(dsClient),
		dsClient:     dsClient,
		lastRun:      lastRun,
		numWorkers:   *numWorkers,
		zipThreshold: zipDownloadThreshold,
		closer: func() {
			dsClient.Close()
			storageClient.Close()
		},
	}, nil
}

func run(ctx context.Context, env *appEnv) error {
	runStartTime := time.Now().UTC()

	logger.InfoContext(ctx, "finding modified Ubuntu vulnerabilities", slog.Time("lastRun", env.lastRun))
	vulnIDs, err := findModifiedUbuntuIDs(ctx, env.gcsStorage, env.lastRun)
	if err != nil {
		return fmt.Errorf("failed finding modified vulnerabilities: %w", err)
	}

	logger.InfoContext(ctx, "discovered vulnerabilities to process", slog.Int("count", len(vulnIDs)))
	if len(vulnIDs) > 0 {
		threshold := cmp.Or(env.zipThreshold, zipDownloadThreshold)
		var allMappings map[string][]string
		if len(vulnIDs) > threshold {
			logger.InfoContext(ctx, "downloading Ubuntu/all.zip for bulk processing", slog.Int("count", len(vulnIDs)), slog.Int("threshold", threshold))
			allMappings, err = extractMappingsFromAllZip(ctx, env.gcsStorage, vulnIDs, env.numWorkers)
		} else {
			logger.InfoContext(ctx, "downloading individual Ubuntu JSON records", slog.Int("count", len(vulnIDs)))
			allMappings, err = extractMappingsFromIndividualFiles(ctx, env.gcsStorage, vulnIDs, env.numWorkers)
		}
		if err != nil {
			return err
		}

		logger.InfoContext(ctx, "extracted binary package mappings", slog.Int("unique_binaries", len(allMappings)))
		if len(allMappings) > 0 {
			if err := saveMappings(ctx, env.ubuntuStore, allMappings); err != nil {
				return fmt.Errorf("failed saving mappings: %w", err)
			}
		}
	}

	if env.dsClient != nil {
		if err := setLastRunInDatastore(ctx, env.dsClient, runStartTime); err != nil {
			return fmt.Errorf("failed recording last run checkpoint: %w", err)
		}
	}

	return nil
}

func extractMappingsFromAllZip(ctx context.Context, gcsStorage clients.CloudStorage, vulnIDs []string, numWorkers int) (map[string][]string, error) {
	zipBytes, err := gcsStorage.ReadObject(ctx, ubuntuAllZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %w", ubuntuAllZipPath, err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed opening zip archive %s: %w", ubuntuAllZipPath, err)
	}

	targetSet := make(map[string]struct{}, len(vulnIDs))
	for _, id := range vulnIDs {
		targetSet[id] = struct{}{}
	}

	var mu sync.Mutex
	allMappings := make(map[string][]string)

	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(numWorkers)

	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		id := strings.TrimSuffix(path.Base(zf.Name), ".json")
		if _, ok := targetSet[id]; !ok {
			continue
		}

		g.Go(func() error {
			rc, err := zf.Open()
			if err != nil {
				return fmt.Errorf("failed opening %s in zip: %w", zf.Name, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("failed reading %s in zip: %w", zf.Name, err)
			}

			return unmarshalAndMerge(data, zf.Name, &mu, allMappings)
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return allMappings, nil
}

func extractMappingsFromIndividualFiles(ctx context.Context, gcsStorage clients.CloudStorage, vulnIDs []string, numWorkers int) (map[string][]string, error) {
	var mu sync.Mutex
	allMappings := make(map[string][]string)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(numWorkers)

	for _, id := range vulnIDs {
		g.Go(func() error {
			objPath := fmt.Sprintf("%s/%s.json", ubuntuPrefix, id)
			data, err := gcsStorage.ReadObject(ctx, objPath)
			if err != nil {
				if errors.Is(err, clients.ErrNotFound) {
					logger.WarnContext(ctx, "vulnerability JSON not found in GCS bucket", slog.String("path", objPath))

					return nil
				}

				return fmt.Errorf("failed reading %s: %w", objPath, err)
			}

			return unmarshalAndMerge(data, objPath, &mu, allMappings)
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return allMappings, nil
}

func unmarshalAndMerge(data []byte, source string, mu *sync.Mutex, allMappings map[string][]string) error {
	var vuln osvschema.Vulnerability
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, &vuln); err != nil {
		return fmt.Errorf("failed unmarshaling %s: %w", source, err)
	}

	recordMappings := ExtractBinaryMappings(&vuln)
	if len(recordMappings) == 0 {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()
	for bin, sources := range recordMappings {
		allMappings[bin] = append(allMappings[bin], sources...)
	}

	return nil
}

func saveMappings(ctx context.Context, store models.UbuntuPackageMappingStore, newMappings map[string][]string) error {
	binaryNames := slices.Sorted(maps.Keys(newMappings))

	existing, err := store.GetMulti(ctx, binaryNames)
	if err != nil {
		return fmt.Errorf("failed getting existing mappings: %w", err)
	}

	toPut := make([]*models.UbuntuPackageMapping, len(binaryNames))
	for i, bin := range binaryNames {
		var existingSources []string
		if i < len(existing) && existing[i] != nil {
			existingSources = existing[i].SourceNames
		}
		merged := slices.Concat(existingSources, newMappings[bin])
		slices.Sort(merged)

		toPut[i] = &models.UbuntuPackageMapping{
			BinaryName:  bin,
			SourceNames: slices.Compact(merged),
		}
	}

	return store.PutMulti(ctx, toPut)
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, span := otel.Tracer("ubuntubinarymapper").Start(context.Background(), "ubuntubinarymapper")
	defer span.End()

	env, err := setup(ctx)
	if err != nil {
		logger.FatalContext(ctx, "failed setting up environment", slog.Any("err", err))
	}
	defer env.closer()

	logger.InfoContext(ctx, "starting ubuntu binary mapper")
	if err := run(ctx, env); err != nil {
		logger.FatalContext(ctx, "failed running ubuntu binary mapper", slog.Any("err", err))
	}
	logger.InfoContext(ctx, "ubuntu binary mapper finished successfully")
}
