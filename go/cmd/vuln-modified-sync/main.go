package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"


	"cloud.google.com/go/datastore"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/tidwall/gjson"
	"google.golang.org/api/iterator"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type ValidationTask struct {
	Vuln *db.Vulnerability
	Key  *datastore.Key
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
		project = "osv-vulnerabilities" 
	}

	datastoreClient, err := datastore.NewClient(ctx, project)
	if err != nil {
		logger.FatalContext(ctx, "Failed to create datastore client", slog.Any("error", err))
	}
	defer datastoreClient.Close()

	taskCh := make(chan ValidationTask, *numWorkers)
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
			worker(ctx, taskCh, datastoreClient, *dir, *dryRun)
		}()
	}

	// Query datastore
	q := datastore.NewQuery("Vulnerability")
	it := datastoreClient.Run(ctx, q)
	processed := 0
	
	for {
		var vuln db.Vulnerability
		key, err := it.Next(&vuln)
		if err == iterator.Done {
			break
		}
		if err != nil {
			logger.ErrorContext(ctx, "Failed to fetch vulnerability", slog.Any("error", err))
			continue
		}

		processed++
		taskCh <- ValidationTask{
			Vuln: &vuln,
			Key:  key,
		}
	}

	close(taskCh)
	wg.Wait()

	logger.InfoContext(ctx, "Sync completed", slog.Int("processed_records", processed))
}

func worker(ctx context.Context, taskCh <-chan ValidationTask, client *datastore.Client, dir string, dryRun bool) {
	for task := range taskCh {
		checkAndUpdate(ctx, client, task, dir, dryRun)
	}
}

func checkAndUpdate(ctx context.Context, client *datastore.Client, task ValidationTask, dir string, dryRun bool) {
	vulnID := task.Key.Name
	
	// Try JSON first, then YAML
	filePath := filepath.Join(dir, vulnID+".json")
	format := "json"
	
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			filePath = filepath.Join(dir, vulnID+".yaml")
			format = "yaml"
			file, err = os.Open(filePath)
			if err != nil {
				if os.IsNotExist(err) {
					// File does not exist, ignore
					return
				}
				logger.ErrorContext(ctx, "Failed to open yaml file", slog.Any("error", err), slog.String("file", filePath))
				return
			}
		} else {
			logger.ErrorContext(ctx, "Failed to open json file", slog.Any("error", err), slog.String("file", filePath))
			return
		}
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read file", slog.Any("error", err), slog.String("file", filePath))
		return
	}

	if format == "yaml" {
		jsonData, err := yaml.ToJSON(data)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert YAML to JSON",
				slog.Any("error", err),
				slog.String("path", filePath))
			return
		}
		data = jsonData
	}

	res := gjson.GetBytes(data, "modified")

	if (!res.Exists()) {
		return
	}

	// Parse the modified time
	modifiedTime, err := parseTime(res.String())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse modified time from file", slog.Any("error", err), slog.String("file", filePath), slog.String("time_str", res.String()))
		return
	}

	if modifiedTime.After(task.Vuln.Modified) {
		logger.InfoContext(ctx, "File modified time is newer", 
			slog.String("id", vulnID), 
			slog.Time("datastore_modified", task.Vuln.Modified), 
			slog.Time("file_modified", modifiedTime))
			
		if !dryRun {
			// Update Datastore
			task.Vuln.Modified = modifiedTime
			task.Vuln.ModifiedRaw = modifiedTime
			
			if _, err := client.Put(ctx, task.Key, task.Vuln); err != nil {
				logger.ErrorContext(ctx, "Failed to update Vulnerability", slog.Any("error", err), slog.String("id", vulnID))
			} else {
				logger.InfoContext(ctx, "Successfully updated datastore", slog.String("id", vulnID))
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
