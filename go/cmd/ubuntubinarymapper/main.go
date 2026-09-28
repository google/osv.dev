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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"slices"
	"strconv"
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
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
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
)

type jobDataEntity struct {
	Value *time.Time `datastore:"value,noindex"`
}

func getLastRunFromDatastore(ctx context.Context, dsClient *datastore.Client) (time.Time, error) {
	key := datastore.NameKey(jobDataKind, jobDataLastRunKey, nil)
	var e jobDataEntity
	if err := dsClient.Get(ctx, key, &e); err != nil {
		return time.Time{}, fmt.Errorf("failed to get JobData for %q: %w", jobDataLastRunKey, err)
	}
	if e.Value == nil {
		return time.Time{}, datastore.ErrNoSuchEntity
	}

	return *e.Value, nil
}

func setLastRunInDatastore(ctx context.Context, dsClient *datastore.Client, t time.Time) error {
	key := datastore.NameKey(jobDataKind, jobDataLastRunKey, nil)
	utcTime := t.UTC()
	e := jobDataEntity{Value: &utcTime}
	if _, err := dsClient.Put(ctx, key, &e); err != nil {
		return fmt.Errorf("failed to put JobData for %q: %w", jobDataLastRunKey, err)
	}

	return nil
}

// findModifiedUbuntuIDs reads Ubuntu/modified_id.csv from the GCS bucket and returns all
// vulnerability IDs modified after lastRun. If lastRun is nil, all IDs in the CSV are returned.
func findModifiedUbuntuIDs(ctx context.Context, gcsStorage clients.CloudStorage, lastRun *time.Time) ([]string, error) {
	csvBytes, err := gcsStorage.ReadObject(ctx, ubuntuModifiedCSVPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %w", ubuntuModifiedCSVPath, err)
	}

	var ids []string
	scanner := bufio.NewScanner(bytes.NewReader(csvBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		tsStr, id, ok := strings.Cut(line, ",")
		if !ok || id == "" {
			continue
		}
		modTime, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			logger.WarnContext(ctx, "invalid timestamp in modified_id.csv", slog.String("line", line), slog.Any("err", err))
			continue
		}
		// Ubuntu/modified_id.csv is sorted by modified date descending.
		if lastRun != nil && !modTime.After(*lastRun) {
			break
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning %s: %w", ubuntuModifiedCSVPath, err)
	}

	return ids, nil
}

// ExtractBinaryMappings extracts a map of binary_name -> set of source_names from a Vulnerability record.
func ExtractBinaryMappings(vuln *osvschema.Vulnerability) map[string]map[string]struct{} {
	mappings := make(map[string]map[string]struct{})
	if vuln == nil {
		return mappings
	}

	for _, affected := range vuln.GetAffected() {
		sourceName := affected.GetPackage().GetName()
		if sourceName == "" {
			continue
		}

		binaryNames := extractBinaryNames(affected.GetEcosystemSpecific())
		binaryNames = append(binaryNames, extractBinaryNames(affected.GetDatabaseSpecific())...)

		for _, binName := range binaryNames {
			binName = strings.TrimSpace(binName)
			if binName == "" {
				continue
			}
			if mappings[binName] == nil {
				mappings[binName] = make(map[string]struct{})
			}
			mappings[binName][sourceName] = struct{}{}
		}
	}

	return mappings
}

func extractBinaryNames(s *structpb.Struct) []string {
	if s == nil || s.GetFields() == nil {
		return nil
	}

	var names []string

	if val, ok := s.GetFields()["binaries"]; ok && val != nil {
		if listVal := val.GetListValue(); listVal != nil {
			for _, item := range listVal.GetValues() {
				if str := item.GetStringValue(); str != "" {
					names = append(names, str)
					continue
				}
				if obj := item.GetStructValue(); obj != nil && obj.GetFields() != nil {
					if binName := obj.GetFields()["binary_name"].GetStringValue(); binName != "" {
						names = append(names, binName)
					} else if name := obj.GetFields()["name"].GetStringValue(); name != "" {
						names = append(names, name)
					}
				}
			}
		}
	}

	if val, ok := s.GetFields()["binary_name"]; ok && val != nil {
		if str := val.GetStringValue(); str != "" {
			names = append(names, str)
		}
	}

	return names
}

// appEnv holds configured services and dependencies.
type appEnv struct {
	gcsStorage   clients.CloudStorage
	ubuntuStore  models.UbuntuPackageMappingStore
	dsClient     *datastore.Client
	localLastRun *time.Time
	numWorkers   int
	zipThreshold int
	closer       func()
}

func setup(ctx context.Context) (*appEnv, error) {
	outputJSON := flag.String("output-json", "", "Path to local JSON file for writing/storing mappings (enables local mode, bypassing Datastore)")
	lastRunFlag := flag.String("last-run", "", "Last job run time in RFC3339 format (used in local mode when -output-json is set)")
	bucketFlag := flag.String("bucket", "", "GCS bucket name containing exported OSV vulnerabilities (defaults to OSV_VULNERABILITIES_BUCKET or osv-vulnerabilities)")
	numWorkersFlag := flag.Int("num-workers", defaultNumWorkers, "Number of worker goroutines")
	flag.Parse()

	numWorkers := *numWorkersFlag
	if val := os.Getenv("NUM_WORKERS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			numWorkers = n
		}
	}

	bucketName := *bucketFlag
	if bucketName == "" {
		bucketName = os.Getenv("OSV_VULNERABILITIES_BUCKET")
	}
	if bucketName == "" {
		bucketName = defaultBucketName
	}

	// Local mode when -output-json is provided
	if *outputJSON != "" {
		var localLastRun *time.Time
		if *lastRunFlag != "" {
			t, err := time.Parse(time.RFC3339Nano, *lastRunFlag)
			if err != nil {
				return nil, fmt.Errorf("invalid -last-run timestamp %q (expected RFC3339): %w", *lastRunFlag, err)
			}
			utcTime := t.UTC()
			localLastRun = &utcTime
		}

		jsonStore, err := jsonstore.New(*outputJSON)
		if err != nil {
			return nil, fmt.Errorf("failed creating JSON store %s: %w", *outputJSON, err)
		}

		storageClient, err := storage.NewClient(ctx, option.WithoutAuthentication())
		if err != nil {
			return nil, fmt.Errorf("failed to create storage client: %w", err)
		}

		return &appEnv{
			gcsStorage:   clients.NewGCSClient(storageClient, bucketName),
			ubuntuStore:  jsonStore,
			dsClient:     nil,
			localLastRun: localLastRun,
			numWorkers:   numWorkers,
			zipThreshold: zipDownloadThreshold,
			closer: func() {
				storageClient.Close()
			},
		}, nil
	}

	// Production Datastore/GCS mode
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		return nil, errors.New("GOOGLE_CLOUD_PROJECT must be set when not running with -output-json")
	}

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	datastoreID := os.Getenv("DATASTORE_DATABASE_ID")
	dsClient, err := datastore.NewClientWithDatabase(ctx, projectID, datastoreID)
	if err != nil {
		storageClient.Close()

		return nil, fmt.Errorf("failed to create datastore client: %w", err)
	}

	return &appEnv{
		gcsStorage:   clients.NewGCSClient(storageClient, bucketName),
		ubuntuStore:  db.NewUbuntuPackageMappingStore(dsClient),
		dsClient:     dsClient,
		localLastRun: nil,
		numWorkers:   numWorkers,
		zipThreshold: zipDownloadThreshold,
		closer: func() {
			dsClient.Close()
			storageClient.Close()
		},
	}, nil
}

func run(ctx context.Context, env *appEnv) error {
	runStartTime := time.Now().UTC()

	var lastRun *time.Time
	if env.dsClient != nil {
		t, err := getLastRunFromDatastore(ctx, env.dsClient)
		if err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
			return fmt.Errorf("failed to get last run time: %w", err)
		}
		if err == nil {
			lastRun = &t
		}
	} else {
		lastRun = env.localLastRun
	}

	if lastRun != nil {
		logger.InfoContext(ctx, "checking for Ubuntu vulnerabilities modified after last run", slog.Time("lastRun", *lastRun))
	} else {
		logger.InfoContext(ctx, "no previous run timestamp set, processing all Ubuntu vulnerabilities")
	}

	vulnIDs, err := findModifiedUbuntuIDs(ctx, env.gcsStorage, lastRun)
	if err != nil {
		return fmt.Errorf("failed finding modified vulnerabilities: %w", err)
	}

	logger.InfoContext(ctx, "discovered vulnerabilities to process", slog.Int("count", len(vulnIDs)))
	if len(vulnIDs) == 0 {
		if env.dsClient != nil {
			logger.InfoContext(ctx, "no vulnerabilities to process, updating last run time in Datastore")

			return setLastRunInDatastore(ctx, env.dsClient, runStartTime)
		}
		logger.InfoContext(ctx, "no vulnerabilities to process")

		return nil
	}

	threshold := env.zipThreshold
	if threshold <= 0 {
		threshold = zipDownloadThreshold
	}

	var allMappings map[string]map[string]struct{}
	if len(vulnIDs) > threshold {
		logger.InfoContext(ctx, "downloading Ubuntu/all.zip for bulk processing", slog.Int("count", len(vulnIDs)), slog.Int("threshold", threshold))
		allMappings, err = extractMappingsFromAllZip(ctx, env.gcsStorage, vulnIDs, env.numWorkers)
		if err != nil {
			return fmt.Errorf("failed processing Ubuntu/all.zip: %w", err)
		}
	} else {
		logger.InfoContext(ctx, "downloading individual Ubuntu JSON records", slog.Int("count", len(vulnIDs)))
		allMappings, err = extractMappingsFromIndividualFiles(ctx, env.gcsStorage, vulnIDs, env.numWorkers)
		if err != nil {
			return fmt.Errorf("failed processing individual Ubuntu files: %w", err)
		}
	}

	logger.InfoContext(ctx, "extracted binary package mappings", slog.Int("unique_binaries", len(allMappings)))

	if len(allMappings) > 0 {
		if err := saveMappings(ctx, env.ubuntuStore, allMappings); err != nil {
			return fmt.Errorf("failed saving mappings: %w", err)
		}
	}

	if env.dsClient != nil {
		if err := setLastRunInDatastore(ctx, env.dsClient, runStartTime); err != nil {
			return fmt.Errorf("failed recording last run checkpoint: %w", err)
		}
		logger.InfoContext(ctx, "successfully completed ubuntu binary mapper run", slog.Time("checkpoint", runStartTime))
	} else {
		logger.InfoContext(ctx, "successfully completed local ubuntu binary mapper run")
	}

	return nil
}

func extractMappingsFromAllZip(ctx context.Context, gcsStorage clients.CloudStorage, vulnIDs []string, numWorkers int) (map[string]map[string]struct{}, error) {
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
	allMappings := make(map[string]map[string]struct{})

	filesChan := make(chan *zip.File, numWorkers*2)
	errChan := make(chan error, numWorkers)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
			for zf := range filesChan {
				rc, err := zf.Open()
				if err != nil {
					select {
					case errChan <- fmt.Errorf("failed opening %s in zip: %w", zf.Name, err):
					default:
					}

					return
				}
				data, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					select {
					case errChan <- fmt.Errorf("failed reading %s in zip: %w", zf.Name, err):
					default:
					}

					return
				}

				var vuln osvschema.Vulnerability
				if err := unmarshaler.Unmarshal(data, &vuln); err != nil {
					select {
					case errChan <- fmt.Errorf("failed unmarshaling %s in zip: %w", zf.Name, err):
					default:
					}

					return
				}

				mergeRecordMappings(&mu, allMappings, ExtractBinaryMappings(&vuln))
			}
		})
	}

	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		id := strings.TrimSuffix(path.Base(zf.Name), ".json")
		if _, ok := targetSet[id]; !ok {
			continue
		}
		filesChan <- zf
	}
	close(filesChan)
	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	return allMappings, nil
}

func extractMappingsFromIndividualFiles(ctx context.Context, gcsStorage clients.CloudStorage, vulnIDs []string, numWorkers int) (map[string]map[string]struct{}, error) {
	var mu sync.Mutex
	allMappings := make(map[string]map[string]struct{})

	jobsChan := make(chan string, numWorkers*2)
	errChan := make(chan error, numWorkers)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
			for id := range jobsChan {
				objPath := fmt.Sprintf("%s/%s.json", ubuntuPrefix, id)
				data, err := gcsStorage.ReadObject(ctx, objPath)
				if err != nil {
					if errors.Is(err, clients.ErrNotFound) {
						logger.WarnContext(ctx, "vulnerability JSON not found in GCS bucket", slog.String("path", objPath))
						continue
					}
					select {
					case errChan <- fmt.Errorf("failed reading %s: %w", objPath, err):
					default:
					}

					return
				}

				var vuln osvschema.Vulnerability
				if err := unmarshaler.Unmarshal(data, &vuln); err != nil {
					select {
					case errChan <- fmt.Errorf("failed unmarshaling %s: %w", objPath, err):
					default:
					}

					return
				}

				mergeRecordMappings(&mu, allMappings, ExtractBinaryMappings(&vuln))
			}
		})
	}

	for _, id := range vulnIDs {
		jobsChan <- id
	}
	close(jobsChan)
	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	return allMappings, nil
}

func mergeRecordMappings(mu *sync.Mutex, allMappings, recordMappings map[string]map[string]struct{}) {
	if len(recordMappings) == 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for bin, sources := range recordMappings {
		if allMappings[bin] == nil {
			allMappings[bin] = make(map[string]struct{})
		}
		for src := range sources {
			allMappings[bin][src] = struct{}{}
		}
	}
}

func saveMappings(ctx context.Context, store models.UbuntuPackageMappingStore, newMappings map[string]map[string]struct{}) error {
	binaryNames := make([]string, 0, len(newMappings))
	for bin := range newMappings {
		binaryNames = append(binaryNames, bin)
	}
	slices.Sort(binaryNames)

	existing, err := store.GetMulti(ctx, binaryNames)
	if err != nil {
		return fmt.Errorf("failed getting existing mappings: %w", err)
	}

	toPut := make([]*models.UbuntuPackageMapping, len(binaryNames))
	for i, bin := range binaryNames {
		srcSet := make(map[string]struct{})
		if i < len(existing) && existing[i] != nil {
			for _, src := range existing[i].SourceNames {
				srcSet[src] = struct{}{}
			}
		}
		for src := range newMappings[bin] {
			srcSet[src] = struct{}{}
		}

		merged := make([]string, 0, len(srcSet))
		for src := range srcSet {
			merged = append(merged, src)
		}
		slices.Sort(merged)

		toPut[i] = &models.UbuntuPackageMapping{
			BinaryName:  bin,
			SourceNames: merged,
		}
	}

	if err := store.PutMulti(ctx, toPut); err != nil {
		return fmt.Errorf("failed writing merged mappings: %w", err)
	}

	return nil
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
