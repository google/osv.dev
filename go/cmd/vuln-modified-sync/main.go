// vuln-modified-sync updates the modified time of vulnerabilities in Datastore to match the modified time of the local files.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/tidwall/gjson"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type SyncTask struct {
	FilePath string
	VulnID   string
}

var osvBucketName = ""

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx := context.Background()

	dryRun := flag.Bool("dry-run", false, "Do not write to Datastore")
	numWorkers := flag.Int("num-workers", 50, "Number of workers to use for checking")
	dir := flag.String("dir", "go/testdir/", "Directory to look for the local files")
	logFile := flag.String("log-file", "", "Path to log file for optimization (to filter IDs)")
	compareDir := flag.String("compare-dir", "", "Directory to compare records against for semantic changes")

	flag.Parse()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		// Use default test project for local testing if not set
		project = "oss-vdb-test"
	}

	if project == "oss-vdb" {
		osvBucketName = "osv-vulnerabilities"
	} else {
		osvBucketName = "osv-test-vulnerabilities"
	}

	datastoreClient, err := datastore.NewClient(ctx, project)
	if err != nil {
		logger.FatalContext(ctx, "Failed to create datastore client", slog.Any("error", err))
	}
	defer datastoreClient.Close()

	// We are posssibly reading a lot of vulnerabilities from GCS, so disable telemetry (disables trace spans).
	storageClient, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "Failed to create GCS client", slog.Any("error", err))
	}
	gcsProvider := clients.NewGCSStorageProvider(storageClient)

	taskCh := make(chan SyncTask, *numWorkers)
	var wg sync.WaitGroup

	logger.InfoContext(ctx, "Starting vulnerability modified sync...",
		slog.Bool("dry_run", *dryRun),
		slog.Int("num_workers", *numWorkers),
		slog.String("dir", *dir),
		slog.String("project", project))

	// Setup worker pool
	for range *numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, taskCh, datastoreClient, gcsProvider, *dryRun, *compareDir)
		}()
	}

	processed := 0

	var idFilter map[string]bool
	if *logFile != "" {
		idFilter = make(map[string]bool)
		f, err := os.Open(*logFile)
		if err != nil {
			logger.FatalContext(ctx, "Failed to open log file", slog.Any("error", err))
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			idx := strings.Index(line, "id=")
			if idx != -1 {
				idStr := line[idx+3:]
				spaceIdx := strings.Index(idStr, " ")
				if spaceIdx != -1 {
					idStr = idStr[:spaceIdx]
				}
				idFilter[idStr] = true
			}
		}
		if err := scanner.Err(); err != nil {
			logger.FatalContext(ctx, "Failed to read log file", slog.Any("error", err))
		}
		logger.InfoContext(ctx, "Loaded IDs from log file", slog.Int("count", len(idFilter)))
	}

	err = filepath.WalkDir(*dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".json" && ext != ".yaml" {
			return nil
		}

		filename := filepath.Base(path)
		vulnID := strings.TrimSuffix(filename, ext)

		if idFilter != nil && !idFilter[vulnID] {
			return nil
		}

		processed++
		taskCh <- SyncTask{
			FilePath: path,
			VulnID:   vulnID,
		}

		return nil
	})

	if err != nil {
		logger.ErrorContext(ctx, "Failed to walk directory", slog.Any("error", err), slog.String("dir", *dir))
	}

	close(taskCh)
	wg.Wait()

	logger.InfoContext(ctx, "Sync completed", slog.Int("processed_files", processed))
}

func worker(ctx context.Context, taskCh <-chan SyncTask, client *datastore.Client, gcsClient *clients.GCSStorageProvider, dryRun bool, compareDir string) {
	for task := range taskCh {
		checkAndUpdate(ctx, client, task, gcsClient, dryRun, compareDir)
	}
}

func checkAndUpdate(ctx context.Context, client *datastore.Client, task SyncTask, gcsClient *clients.GCSStorageProvider, dryRun bool, compareDir string) {
	file, err := os.Open(task.FilePath)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to open file", slog.Any("error", err), slog.String("file", task.FilePath))
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read file", slog.Any("error", err), slog.String("file", task.FilePath))
		return
	}

	if filepath.Ext(task.FilePath) == ".yaml" {
		jsonData, err := yaml.ToJSON(data)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert YAML to JSON",
				slog.Any("error", err),
				slog.String("path", task.FilePath))

			return
		}
		data = jsonData
	}

	res := gjson.GetBytes(data, "modified")
	if !res.Exists() {
		return
	}

	// Parse the modified time from file
	fileModifiedTime, err := parseTime(res.String())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse modified time from file", slog.Any("error", err), slog.String("file", task.FilePath), slog.String("time_str", res.String()))
		return
	}

	if compareDir != "" {
		compareFile := filepath.Join(compareDir, task.VulnID+".json")
		compareData, err := os.ReadFile(compareFile)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to read compare file", slog.Any("error", err), slog.String("file", compareFile))
			return
		}

		var m1, m2 map[string]any
		if err := json.Unmarshal(data, &m1); err != nil {
			logger.ErrorContext(ctx, "Failed to unmarshal source data for comparison", slog.Any("error", err))
			return
		}
		if err := json.Unmarshal(compareData, &m2); err != nil {
			logger.ErrorContext(ctx, "Failed to unmarshal compare data", slog.Any("error", err))
			return
		}

		delete(m1, "modified")
		delete(m2, "modified")

		m1Strip := removeEmptySlicesAndMaps(m1)
		m2Strip := removeEmptySlicesAndMaps(m2)

		if cmp.Equal(m1Strip, m2Strip, cmpopts.EquateEmpty()) {
			logger.InfoContext(ctx, "Records match semantically", slog.String("id", task.VulnID))
		} else {
			// diff := cmp.Diff(m1, m2, cmpopts.EquateEmpty())
			logger.InfoContext(ctx, "Records differ semantically, setting modified to now", slog.String("id", task.VulnID))
			fileModifiedTime = time.Now()
		}
	}

	// Fetch vulnerability from Datastore
	key := datastore.NameKey("Vulnerability", task.VulnID, nil)
	var vuln db.Vulnerability
	if err := client.Get(ctx, key, &vuln); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			logger.InfoContext(ctx, "Vulnerability not found in datastore", slog.String("id", task.VulnID))
		} else {
			logger.ErrorContext(ctx, "Failed to get Vulnerability from datastore", slog.Any("error", err), slog.String("id", task.VulnID))
		}

		return
	}

	// Minus 1 minute to file modified time to avoid any precision issues
	if fileModifiedTime.Add(time.Minute * -1).After(vuln.Modified) {
		logger.InfoContext(ctx, "File modified time is newer",
			slog.String("id", task.VulnID),
			slog.Time("datastore_modified", vuln.Modified),
			slog.Time("file_modified", fileModifiedTime))

		if !dryRun {
			// Update Datastore
			vuln.Modified = fileModifiedTime
			bkt := gcsClient.Bucket(osvBucketName)
			obj, err := bkt.ReadObject(ctx, "all/pb/"+task.VulnID+".pb")
			if err != nil {
				logger.ErrorContext(ctx, "Failed to read object", slog.Any("error", err), slog.String("id", task.VulnID))
				return
			}
			// Parse proto obj
			var vulnProto osvschema.Vulnerability
			if err := proto.Unmarshal(obj, &vulnProto); err != nil {
				logger.ErrorContext(ctx, "Failed to unmarshal proto", slog.Any("error", err), slog.String("id", task.VulnID))
				return
			}
			vulnProto.Modified = timestamppb.New(fileModifiedTime)
			data, err := proto.Marshal(&vulnProto)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to marshal proto", slog.Any("error", err), slog.String("id", task.VulnID))
				return
			}
			if err := bkt.WriteObject(ctx, "all/pb/"+task.VulnID+".pb", data, &clients.WriteOptions{CustomTime: &fileModifiedTime}); err != nil {
				logger.ErrorContext(ctx, "Failed to write object", slog.Any("error", err), slog.String("id", task.VulnID))
				return
			}
			logger.InfoContext(ctx, "Successfully updated gcs object", slog.String("id", task.VulnID))
			if _, err := client.Put(ctx, key, &vuln); err != nil {
				logger.ErrorContext(ctx, "Failed to update Vulnerability", slog.Any("error", err), slog.String("id", task.VulnID))
			} else {
				logger.InfoContext(ctx, "Successfully updated datastore", slog.String("id", task.VulnID))
			}
		}
	}
}

func parseTime(timeStr string) (time.Time, error) {
	// Try a few common formats, primarily RFC3339
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999999Z",
	}

	for _, format := range formats {
		t, err := time.Parse(format, timeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time string %q", timeStr)
}

func removeEmptySlicesAndMaps(v interface{}) interface{} {
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return v
	}

	switch val.Kind() {
	case reflect.Map:
		if val.Len() == 0 {
			return nil
		}
		newMap := reflect.MakeMap(val.Type())
		iter := val.MapRange()
		hasValues := false
		for iter.Next() {
			k := iter.Key()
			v := removeEmptySlicesAndMaps(iter.Value().Interface())
			if v != nil {
				rt := reflect.ValueOf(v)
				if rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
					if rt.Len() > 0 {
						newMap.SetMapIndex(k, reflect.ValueOf(v))
						hasValues = true
					}
				} else {
					newMap.SetMapIndex(k, reflect.ValueOf(v))
					hasValues = true
				}
			}
		}
		if !hasValues {
			return nil
		}
		return newMap.Interface()

	case reflect.Slice:
		if val.Len() == 0 {
			return nil
		}
		sliceType := reflect.SliceOf(val.Type().Elem())
		newSlice := reflect.MakeSlice(sliceType, 0, val.Len())
		hasValues := false
		for i := 0; i < val.Len(); i++ {
			elem := removeEmptySlicesAndMaps(val.Index(i).Interface())
			if elem != nil {
				newSlice = reflect.Append(newSlice, reflect.ValueOf(elem))
				hasValues = true
			}
		}
		if !hasValues {
			return nil
		}
		return newSlice.Interface()

	default:
		return v
	}
}
