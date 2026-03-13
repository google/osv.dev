package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/datastore"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/tidwall/gjson"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type SyncTask struct {
	FilePath string
	VulnID   string
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx := context.Background()

	dryRun := flag.Bool("dry-run", false, "Do not write to Datastore")
	numWorkers := flag.Int("num-workers", 50, "Number of workers to use for checking")
	dir := flag.String("dir", "go/testdir/", "Directory to look for the local files")

	flag.Parse()

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		// Use default test project for local testing if not set
		project = "oss-vdb-test"
	}

	datastoreClient, err := datastore.NewClient(ctx, project)
	if err != nil {
		logger.FatalContext(ctx, "Failed to create datastore client", slog.Any("error", err))
	}
	defer datastoreClient.Close()

	taskCh := make(chan SyncTask, *numWorkers)
	var wg sync.WaitGroup

	logger.InfoContext(ctx, "Starting vulnerability modified sync...",
		slog.Bool("dry_run", *dryRun),
		slog.Int("num_workers", *numWorkers),
		slog.String("dir", *dir),
		slog.String("project", project))

	// Setup worker pool
	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, taskCh, datastoreClient, *dryRun)
		}()
	}

	processed := 0

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

func worker(ctx context.Context, taskCh <-chan SyncTask, client *datastore.Client, dryRun bool) {
	for task := range taskCh {
		checkAndUpdate(ctx, client, task, dryRun)
	}
}

func checkAndUpdate(ctx context.Context, client *datastore.Client, task SyncTask, dryRun bool) {
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

	// Fetch vulnerability from Datastore
	key := datastore.NameKey("Vulnerability", task.VulnID, nil)
	var vuln db.Vulnerability
	if err := client.Get(ctx, key, &vuln); err != nil {
		if err == datastore.ErrNoSuchEntity {
			logger.InfoContext(ctx, "Vulnerability not found in datastore", slog.String("id", task.VulnID))
		} else {
			logger.ErrorContext(ctx, "Failed to get Vulnerability from datastore", slog.Any("error", err), slog.String("id", task.VulnID))
		}
		return
	}

	if fileModifiedTime.After(vuln.Modified) {
		logger.InfoContext(ctx, "File modified time is newer",
			slog.String("id", task.VulnID),
			slog.Time("datastore_modified", vuln.Modified),
			slog.Time("file_modified", fileModifiedTime))

		if !dryRun {
			// Update Datastore
			vuln.Modified = fileModifiedTime
			vuln.ModifiedRaw = fileModifiedTime

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
