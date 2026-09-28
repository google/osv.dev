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
// vulnerability records, extracts binary-to-source package name mappings,
// and saves them to Datastore.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	jobDataLastRunKey = "ubuntu_binary_mapper_last_run"
	defaultNumWorkers = 20
)

var ubuntuSources = []string{
	"ubuntu-usn",
	"ubuntu-cve",
	"ubuntu-lsn",
}

// UbuntuFinder finds vulnerability IDs that need processing.
type UbuntuFinder interface {
	FindUbuntuVulnerabilities(ctx context.Context, lastRun *time.Time) ([]string, error)
}

type datastoreUbuntuFinder struct {
	dsClient  *datastore.Client
	vulnStore models.VulnerabilityStore
}

func (f *datastoreUbuntuFinder) FindUbuntuVulnerabilities(ctx context.Context, lastRun *time.Time) ([]string, error) {
	if lastRun == nil {
		// Initial full run: list records from all Ubuntu sources.
		var allIDs []string
		for _, source := range ubuntuSources {
			logger.InfoContext(ctx, "listing vulnerabilities from source", slog.String("source", source))
			for ref, err := range f.vulnStore.ListBySource(ctx, source, false) {
				if err != nil {
					return nil, fmt.Errorf("failed listing source %s: %w", source, err)
				}
				allIDs = append(allIDs, ref.ID)
			}
		}
		slices.Sort(allIDs)

		return slices.Compact(allIDs), nil
	}

	// Incremental run: query Vulnerability where modified > lastRun.
	logger.InfoContext(ctx, "querying modified vulnerabilities", slog.Time("lastRun", *lastRun))
	q := datastore.NewQuery("Vulnerability").FilterField("modified", ">", *lastRun)
	it := f.dsClient.Run(ctx, q)

	var matchedIDs []string
	for {
		var v db.Vulnerability
		key, err := it.Next(&v)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query modified vulnerabilities: %w", err)
		}

		if isUbuntuRecord(v.SourceID, key.Name) {
			matchedIDs = append(matchedIDs, key.Name)
		}
	}

	slices.Sort(matchedIDs)

	return slices.Compact(matchedIDs), nil
}

func isUbuntuRecord(sourceID, id string) bool {
	if strings.HasPrefix(sourceID, "ubuntu-") {
		return true
	}
	for _, source := range ubuntuSources {
		if strings.HasPrefix(sourceID, source+":") {
			return true
		}
	}

	return strings.HasPrefix(id, "USN-") || strings.HasPrefix(id, "UBUNTU-") || strings.HasPrefix(id, "LSN-")
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
	finder       UbuntuFinder
	vulnStore    models.VulnerabilityStore
	ubuntuStore  models.UbuntuPackageMappingStore
	jobDataStore models.JobDataStore
	numWorkers   int
	closer       func()
}

type localFileVulnStore struct {
	models.UnimplementedVulnerabilityStore

	files map[string]string
}

func (s *localFileVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	path, ok := s.files[id]
	if !ok {
		return nil, models.ErrNotFound
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %w", path, err)
	}

	var vuln osvschema.Vulnerability
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshaler.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("failed unmarshaling %s: %w", path, err)
	}

	return &vuln, nil
}

type localFinder struct {
	ids []string
}

func (f *localFinder) FindUbuntuVulnerabilities(_ context.Context, _ *time.Time) ([]string, error) {
	return f.ids, nil
}

func setup(ctx context.Context) (*appEnv, error) {
	outputJSON := flag.String("output-json", "", "Path to local JSON file for writing/storing mappings and checkpoint (bypasses Datastore)")
	inputFile := flag.String("input-file", "", "Path to local OSV vulnerability JSON file to process (bypasses Datastore/GCS)")
	inputDir := flag.String("input-dir", "", "Path to local directory containing OSV vulnerability JSON files to process (bypasses Datastore/GCS)")
	numWorkersFlag := flag.Int("num-workers", defaultNumWorkers, "Number of worker goroutines")
	flag.Parse()

	numWorkers := *numWorkersFlag
	if val := os.Getenv("NUM_WORKERS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			numWorkers = n
		}
	}

	// Local file input mode
	if *inputFile != "" || *inputDir != "" {
		files := make(map[string]string)
		var ids []string
		unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}

		if *inputFile != "" {
			data, err := os.ReadFile(*inputFile)
			if err != nil {
				return nil, fmt.Errorf("failed reading input file %s: %w", *inputFile, err)
			}
			var vuln osvschema.Vulnerability
			id := filepath.Base(*inputFile)
			id = strings.TrimSuffix(id, filepath.Ext(id))
			if err := unmarshaler.Unmarshal(data, &vuln); err == nil && vuln.GetId() != "" {
				id = vuln.GetId()
			}
			files[id] = *inputFile
			ids = append(ids, id)
		}

		if *inputDir != "" {
			entries, err := os.ReadDir(*inputDir)
			if err != nil {
				return nil, fmt.Errorf("failed reading input dir %s: %w", *inputDir, err)
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				filePath := filepath.Join(*inputDir, entry.Name())
				data, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}
				var vuln osvschema.Vulnerability
				id := strings.TrimSuffix(entry.Name(), ".json")
				if err := unmarshaler.Unmarshal(data, &vuln); err == nil && vuln.GetId() != "" {
					id = vuln.GetId()
				}
				files[id] = filePath
				ids = append(ids, id)
			}
		}

		slices.Sort(ids)
		ids = slices.Compact(ids)

		storePath := *outputJSON
		if storePath == "" {
			storePath = "ubuntu_package_mappings.json"
		}
		jsonStore, err := jsonstore.New(storePath)
		if err != nil {
			return nil, fmt.Errorf("failed creating JSON store %s: %w", storePath, err)
		}

		return &appEnv{
			finder:       &localFinder{ids: ids},
			vulnStore:    &localFileVulnStore{files: files},
			ubuntuStore:  jsonStore,
			jobDataStore: jsonStore,
			numWorkers:   numWorkers,
			closer:       func() {},
		}, nil
	}

	// Production Datastore/GCS mode
	var ubuntuStore models.UbuntuPackageMappingStore
	var jobDataStore models.JobDataStore

	if *outputJSON != "" {
		jsonStore, err := jsonstore.New(*outputJSON)
		if err != nil {
			return nil, fmt.Errorf("failed creating JSON store %s: %w", *outputJSON, err)
		}
		ubuntuStore = jsonStore
		jobDataStore = jsonStore
	}

	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		return nil, errors.New("GOOGLE_CLOUD_PROJECT must be set")
	}

	bucketName, ok := os.LookupEnv("OSV_VULNERABILITIES_BUCKET")
	if !ok {
		return nil, errors.New("OSV_VULNERABILITIES_BUCKET must be set")
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

	vulnStore := db.NewVulnerabilityStore(db.VulnStoreConfig{
		Client: dbClientWrapper(dsClient),
		GCS:    clients.NewGCSClient(storageClient, bucketName),
	})

	if ubuntuStore == nil {
		ubuntuStore = db.NewUbuntuPackageMappingStore(dsClient)
	}
	if jobDataStore == nil {
		jobDataStore = db.NewJobDataStore(dsClient)
	}

	finder := &datastoreUbuntuFinder{
		dsClient:  dsClient,
		vulnStore: vulnStore,
	}

	return &appEnv{
		finder:       finder,
		vulnStore:    vulnStore,
		ubuntuStore:  ubuntuStore,
		jobDataStore: jobDataStore,
		numWorkers:   numWorkers,
		closer: func() {
			dsClient.Close()
			storageClient.Close()
		},
	}, nil
}

func dbClientWrapper(cl *datastore.Client) *datastore.Client {
	return cl
}

func run(ctx context.Context, env *appEnv) error {
	runStartTime := time.Now().UTC()

	var lastRun *time.Time
	lastRunTime, err := env.jobDataStore.GetLastRun(ctx, jobDataLastRunKey)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return fmt.Errorf("failed to get last run time: %w", err)
	}
	if err == nil {
		lastRun = &lastRunTime
	}

	vulnIDs, err := env.finder.FindUbuntuVulnerabilities(ctx, lastRun)
	if err != nil {
		return fmt.Errorf("failed finding vulnerabilities: %w", err)
	}

	logger.InfoContext(ctx, "discovered vulnerabilities to process", slog.Int("count", len(vulnIDs)))
	if len(vulnIDs) == 0 {
		logger.InfoContext(ctx, "no vulnerabilities to process, updating last run time")

		return env.jobDataStore.SetLastRun(ctx, jobDataLastRunKey, runStartTime)
	}

	var mu sync.Mutex
	allMappings := make(map[string]map[string]struct{})

	jobsChan := make(chan string, env.numWorkers*2)
	errChan := make(chan error, env.numWorkers)

	var wg sync.WaitGroup
	for range env.numWorkers {
		wg.Go(func() {
			for id := range jobsChan {
				vuln, err := env.vulnStore.GetFull(ctx, id)
				if err != nil {
					if errors.Is(err, models.ErrNotFound) {
						logger.WarnContext(ctx, "vulnerability not found in storage", slog.String("id", id))
						continue
					}
					select {
					case errChan <- fmt.Errorf("failed fetching %s: %w", id, err):
					default:
					}

					return
				}

				recordMappings := ExtractBinaryMappings(vuln)
				if len(recordMappings) > 0 {
					mu.Lock()
					for bin, sources := range recordMappings {
						if allMappings[bin] == nil {
							allMappings[bin] = make(map[string]struct{})
						}
						for src := range sources {
							allMappings[bin][src] = struct{}{}
						}
					}
					mu.Unlock()
				}
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
		return <-errChan
	}

	logger.InfoContext(ctx, "extracted binary package mappings", slog.Int("unique_binaries", len(allMappings)))

	if len(allMappings) > 0 {
		if err := saveMappings(ctx, env.ubuntuStore, allMappings); err != nil {
			return fmt.Errorf("failed saving mappings: %w", err)
		}
	}

	if err := env.jobDataStore.SetLastRun(ctx, jobDataLastRunKey, runStartTime); err != nil {
		return fmt.Errorf("failed recording last run checkpoint: %w", err)
	}

	logger.InfoContext(ctx, "successfully completed ubuntu binary mapper run", slog.Time("checkpoint", runStartTime))

	return nil
}

func saveMappings(ctx context.Context, store models.UbuntuPackageMappingStore, newMappings map[string]map[string]struct{}) error {
	binaryNames := make([]string, 0, len(newMappings))
	for bin := range newMappings {
		binaryNames = append(binaryNames, bin)
	}

	const chunkSize = 500
	for i := 0; i < len(binaryNames); i += chunkSize {
		end := min(i+chunkSize, len(binaryNames))
		chunk := binaryNames[i:end]

		existing, err := store.GetMulti(ctx, chunk)
		if err != nil {
			return fmt.Errorf("failed getting existing mappings: %w", err)
		}

		toPut := make([]*models.UbuntuPackageMapping, len(chunk))
		for j, bin := range chunk {
			srcSet := make(map[string]struct{})
			if j < len(existing) && existing[j] != nil {
				for _, src := range existing[j].SourceNames {
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

			toPut[j] = &models.UbuntuPackageMapping{
				BinaryName:  bin,
				SourceNames: merged,
			}
		}

		if err := store.PutMulti(ctx, toPut); err != nil {
			return fmt.Errorf("failed writing merged mappings: %w", err)
		}
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
