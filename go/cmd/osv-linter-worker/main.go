// osv-linter-worker
//
// # Worker for osv-linter
//
// This worker is responsible for running osv-linter and uploading the results to GCS.
// It also writes the results to Datastore.
//
// Usage:
//
//	go run main.go -work_dir=/tmp -local_data=/path/to/all.zip -linter_binary=osv-linter -dry_run=true
//
// Options:
//
//	work_dir: Working directory
//	local_data: Path to local all.zip or directory containing OSV data
//	linter_binary: Path to osv-linter binary
//	dry_run: Dry run mode (no GCS upload or Datastore writes)
//
// Environment variables:
//
//	GCP_PROJECT: GCP project ID
package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sync/atomic"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/models"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

const (
	vulnBucket         = "osv-test-vulnerabilities"
	zipFilePath        = "all.zip"
	linterExportBucket = "osv-test-public-import-logs"
	linterResultDir    = "linter-result"
	gcpProject         = "oss-vdb-test"
	maxConcurrency     = 32 // Adjust based on machine limits
	batchSize          = 500
)

var errorCodeMapping = map[string]models.ImportFindings{
	"SCH:001": models.ImportFindingsInvalidJSON,
	"REC:001": models.ImportFindingsInvalidRecord,
	"REC:002": models.ImportFindingsInvalidAliases,
	"REC:003": models.ImportFindingsInvalidUpstream,
	"REC:004": models.ImportFindingsInvalidRelated,
	"RNG:001": models.ImportFindingsInvalidRange,
	"RNG:002": models.ImportFindingsInvalidRange,
	"PKG:001": models.ImportFindingsInvalidPackage,
	"PKG:002": models.ImportFindingsInvalidVersion,
	"PKG:003": models.ImportFindingsInvalidPURL,
}

func main() {
	if err := run(); err != nil {
		logger.Fatal("error running linter worker", slog.Any("err", err))
	}
}

func run() error {
	workDir := flag.String("work_dir", "/tmp", "Working directory")
	localData := flag.String("local_data", "", "Path to local all.zip or directory containing OSV data")
	linterBinary := flag.String("linter_binary", "osv-linter", "Path to osv-linter binary")
	dryRun := flag.Bool("dry_run", true, "Dry run mode (no GCS upload or Datastore writes)")
	flag.Parse()

	ctx := context.Background()
	dsClient, err := datastore.NewClient(ctx, gcpProject)
	if err != nil {
		return fmt.Errorf("failed to create datastore client: %w", err)
	}
	defer dsClient.Close()

	prefixToSource, err := constructPrefixToSourceMap(ctx, dsClient)
	if err != nil {
		return fmt.Errorf("failed to construct prefix map: %w", err)
	}

	tmpDir := filepath.Join(*workDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dataDir, err := prepareData(ctx, tmpDir, *localData)
	if err != nil {
		return fmt.Errorf("failed to prepare data: %w", err)
	}

	linterOutput, err := runLinter(*linterBinary, dataDir)
	if err != nil {
		return fmt.Errorf("linter execution failed: %w", err)
	}

	if err := processLinterResult(ctx, dsClient, linterOutput, prefixToSource, *dryRun); err != nil {
		return fmt.Errorf("failed to process linter result: %w", err)
	}

	return nil
}

func constructPrefixToSourceMap(ctx context.Context, client *datastore.Client) (map[string]string, error) {
	prefixToSource := make(map[string]string)
	query := datastore.NewQuery("SourceRepository")
	it := client.Run(ctx, query)
	for {
		var source models.SourceRepository
		_, err := it.Next(&source)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, prefix := range source.DBPrefix {
			prefixToSource[prefix] = source.Name
		}
	}

	return prefixToSource, nil
}

func prepareData(ctx context.Context, tmpDir string, localData string) (string, error) {
	if localData != "" {
		info, err := os.Stat(localData)
		if err != nil {
			return "", fmt.Errorf("failed to stat local data: %w", err)
		}
		if info.IsDir() {
			return localData, nil
		}
		// Assume zip file
		logger.Info("Unzipping local file", slog.String("localData", localData), slog.String("tmpDir", tmpDir))
		if err := unzip(localData, tmpDir); err != nil {
			return "", err
		}

		return tmpDir, nil
	}

	// Download from GCS
	logger.Info("Downloading file", slog.String("zipFilePath", zipFilePath), slog.String("vulnBucket", vulnBucket))
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	bucket := client.Bucket(vulnBucket)
	rc, err := bucket.Object(zipFilePath).NewReader(ctx)
	if err != nil {
		return "", err
	}
	defer rc.Close()

	zipDest := filepath.Join(tmpDir, zipFilePath)
	outFile, err := os.Create(zipDest)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(outFile, rc); err != nil {
		outFile.Close()
		return "", err
	}
	outFile.Close()

	logger.Info("Unzipping file", slog.String("zipDest", zipDest), slog.String("tmpDir", tmpDir))
	if err := unzip(zipDest, tmpDir); err != nil {
		return "", err
	}

	return tmpDir, nil
}

func safeJoin(base, name string) (string, error) {
	newFilePath := filepath.Join(base, name)

	if rel, err := filepath.Rel(base, newFilePath); err != nil || rel == "" {
		return "", fmt.Errorf("path %s is not a subpath of %s", name, base)
	}

	return newFilePath, nil
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	dest, err = filepath.Abs(dest)
	if err != nil {
		return err
	}
	cleanedDest := filepath.Clean(dest)

	for _, f := range r.File {
		fpath, err := safeJoin(cleanedDest, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}

			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		// Limit file size to 1GB to prevent decompression bombs (G110)
		// OSV JSON files should be much smaller than this.
		const maxFileSize = 1024 * 1024 * 1024 // 1GB
		_, err = io.Copy(outFile, io.LimitReader(rc, maxFileSize))
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func runLinter(binaryPath, dataDir string) ([]byte, error) {
	// If binaryPath has no path separators, check if it exists in CWD.
	// exec.Command only looks in PATH for names without separators.
	if !strings.Contains(binaryPath, string(os.PathSeparator)) {
		if _, err := os.Stat(binaryPath); err == nil {
			binaryPath = "./" + binaryPath
		}
	}

	cmd := exec.Command(binaryPath, "record", "check", "--json", "--parallel", "10", "--collection", "offline", dataDir)
	logger.Info("Executing linter", slog.String("cmd", cmd.String()))
	output, err := cmd.Output() // err usually just indicates that there were findings
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			logger.Error("Linter execution failed unexpectedly", slog.Any("err", err))
			return nil, err
		}
	}

	return output, nil
}

func processLinterResult(ctx context.Context, dsClient *datastore.Client, output []byte, prefixToSource map[string]string, dryRun bool) error {
	var results map[string][]map[string]any
	if err := json.Unmarshal(output, &results); err != nil {
		return fmt.Errorf("failed to parse linter output: %w", err)
	}

	logger.Info("Successfully parsed linter output")

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := uploadRecordToBucket(ctx, results, prefixToSource, dryRun); err != nil {
			logger.Error("Failed to upload results to bucket", slog.Any("err", err))
			return nil
		}
		return nil
	})

	// 2. Fetch existing findings (Async)
	existingIDs := make(map[string]*datastore.Key)
	g.Go(func() error {
		query := datastore.NewQuery("ImportFinding").KeysOnly()
		keys, err := dsClient.GetAll(ctx, query, nil)
		if err != nil {
			return fmt.Errorf("failed to fetch existing findings: %w", err)
		}
		for _, key := range keys {
			existingIDs[key.Name] = key
		}

		return nil
	})

	// 3. Process findings and update Datastore (Parallel)
	linterBugs := make(map[string]bool)
	findingsToPut := make([]*models.ImportFinding, 0, len(results))
	now := time.Now().UTC()

	// Prepare findings in memory first (CPU bound)
	for filename, findingsList := range results {
		bugID := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		linterBugs[bugID] = true

		if len(findingsList) == 0 {
			continue
		}

		uniqueFindings := make(map[models.ImportFindings]bool)
		for _, f := range findingsList {
			code, ok := f["Code"].(string)
			if !ok {
				code = "UNKNOWN_CODE"
			}
			importFinding := errorCodeMapping[code]
			if importFinding == 0 {
				importFinding = models.ImportFindingsNone
			}
			uniqueFindings[importFinding] = true
		}

		var sortedFindings []models.ImportFindings
		for f := range uniqueFindings {
			sortedFindings = append(sortedFindings, f)
		}
		sort.Slice(sortedFindings, func(i, j int) bool {
			return sortedFindings[i] < sortedFindings[j]
		})

		prefix := strings.Split(bugID, "-")[0] + "-"
		source := prefixToSource[prefix]

		key := datastore.NameKey("ImportFinding", bugID, nil)
		finding := &models.ImportFinding{
			Key:         key,
			BugID:       bugID,
			Source:      source,
			Findings:    sortedFindings,
			LastAttempt: now,
		}
		findingsToPut = append(findingsToPut, finding)
	}

	// Launch workers to process findingsToPut

	// Create a channel for batches
	batchChan := make(chan []*models.ImportFinding, len(findingsToPut)/batchSize+1)

	// Fill channel
	for i := 0; i < len(findingsToPut); i += batchSize {
		end := i + batchSize
		if end > len(findingsToPut) {
			end = len(findingsToPut)
		}
		batchChan <- findingsToPut[i:end]
	}
	close(batchChan)

	// Start workers
	var updatedCount int64
	for range maxConcurrency {
		g.Go(func() error {
			for batch := range batchChan {
				if err := processBatch(ctx, dsClient, batch, now, &updatedCount, dryRun); err != nil {
					return err
				}
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	logger.Info("Updated/Created findings", slog.Int64("count", updatedCount))

	var keysToDelete []*datastore.Key
	for id, key := range existingIDs {
		if !linterBugs[id] {
			keysToDelete = append(keysToDelete, key)
			logger.Debug("Deleting stale finding", slog.Any("key", key))
		}
	}

	if len(keysToDelete) > 0 {
		if dryRun {
			logger.Info("Dry run: skipping deletion of stale findings", slog.Int("count", len(keysToDelete)))
		} else {
			// Delete in batches
			deleteG, ctx := errgroup.WithContext(ctx)
			deleteBatchChan := make(chan []*datastore.Key, len(keysToDelete)/batchSize+1)

			for i := 0; i < len(keysToDelete); i += batchSize {
				end := i + batchSize
				if end > len(keysToDelete) {
					end = len(keysToDelete)
				}
				deleteBatchChan <- keysToDelete[i:end]
			}
			close(deleteBatchChan)

			for range maxConcurrency {
				deleteG.Go(func() error {
					for batch := range deleteBatchChan {
						if err := dsClient.DeleteMulti(ctx, batch); err != nil {
							return err
						}
					}

					return nil
				})
			}
			if err := deleteG.Wait(); err != nil {
				return fmt.Errorf("failed to delete stale findings: %w", err)
			}
		}
	}

	return nil
}

func processBatch(ctx context.Context, dsClient *datastore.Client, batch []*models.ImportFinding, now time.Time, updatedCount *int64, dryRun bool) error {
	keys := make([]*datastore.Key, len(batch))
	for j, f := range batch {
		keys[j] = f.Key
	}

	existing := make([]*models.ImportFinding, len(batch))
	if err := dsClient.GetMulti(ctx, keys, existing); err != nil {
		var multiErr datastore.MultiError
		if errors.As(err, &multiErr) {
			for j, e := range multiErr {
				if errors.Is(e, datastore.ErrNoSuchEntity) {
					batch[j].FirstSeen = now
					logger.Info("New finding", slog.String("bugID", batch[j].BugID))
				} else if e != nil {
					return err
				} else {
					batch[j].FirstSeen = existing[j].FirstSeen
					if equalFindings(batch[j].Findings, existing[j].Findings) {
						batch[j] = nil // Skip
					}
				}
			}
		} else {
			return err
		}
	}

	var cleanBatch []*models.ImportFinding
	var cleanKeys []*datastore.Key
	for _, f := range batch {
		if f != nil {
			cleanBatch = append(cleanBatch, f)
			cleanKeys = append(cleanKeys, f.Key)
		}
	}

	if len(cleanBatch) > 0 {
		if dryRun {
			logger.Info("Dry run: skipping put of findings", slog.Int("count", len(cleanBatch)))
		} else {
			if _, err := dsClient.PutMulti(ctx, cleanKeys, cleanBatch); err != nil {
				return err
			}
		}
		atomic.AddInt64(updatedCount, int64(len(cleanBatch)))
	}

	return nil
}

func equalFindings(a, b []models.ImportFindings) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func uploadRecordToBucket(ctx context.Context, results map[string][]map[string]any, prefixToSource map[string]string, dryRun bool) error {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	bucket := client.Bucket(linterExportBucket)

	// List existing objects to determine what needs to be deleted later
	existingObjects := make(map[string]bool)
	it := bucket.Objects(ctx, &storage.Query{Prefix: linterResultDir})
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return err
		}
		existingObjects[attrs.Name] = true
	}

	sourceResults := make(map[string]map[string][]map[string]any)
	for filename, findings := range results {
		bugID := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		prefix := strings.Split(bugID, "-")[0] + "-"
		source := prefixToSource[prefix]
		if source == "" {
			continue
		}
		if _, ok := sourceResults[source]; !ok {
			sourceResults[source] = make(map[string][]map[string]any)
		}
		sourceResults[source][filename] = findings
	}

	// Parallel upload
	gUpload, ctx := errgroup.WithContext(ctx)
	type uploadTask struct {
		source string
		data   []byte
	}
	uploadChan := make(chan uploadTask, len(sourceResults))

	for source, res := range sourceResults {
		if len(res) == 0 {
			continue
		}
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		uploadChan <- uploadTask{source: source, data: data}
	}
	close(uploadChan)

	for range maxConcurrency {
		gUpload.Go(func() error {
			for task := range uploadChan {
				targetPath := filepath.Join(linterResultDir, task.source, "result.json")

				if dryRun {
					logger.Info("Dry run: skipping upload", slog.String("targetPath", targetPath), slog.String("source", task.source))
					continue
				}

				w := bucket.Object(targetPath).NewWriter(ctx)
				w.ContentType = "application/json"
				if _, err := w.Write(task.data); err != nil {
					w.Close()
					return err
				}
				if err := w.Close(); err != nil {
					return err
				}
				logger.Info("Uploaded results for "+task.source, slog.String("source", task.source))
			}
			return nil
		})
	}

	if err := gUpload.Wait(); err != nil {
		return err
	}

	// Calculate what to delete
	var toDelete []string
	for objName := range existingObjects {
		relPath, err := filepath.Rel(linterResultDir, objName)
		if err != nil {
			continue
		}
		parts := strings.Split(relPath, string(filepath.Separator))
		if len(parts) < 2 {
			continue
		}
		source := parts[0]
		if _, ok := sourceResults[source]; !ok {
			toDelete = append(toDelete, objName)
			logger.Info("Found stale object", slog.String("name", objName), slog.String("source", source))
		}
	}

	if len(toDelete) == 0 {
		return nil
	}

	if dryRun {
		logger.Info("Dry run: skipping deletion of objects", slog.Int("count", len(toDelete)))
		return nil
	}

	// Parallel delete
	gDelete, ctx := errgroup.WithContext(ctx)
	deleteChan := make(chan string, len(toDelete))
	for _, name := range toDelete {
		deleteChan <- name
	}
	close(deleteChan)

	for range maxConcurrency {
		gDelete.Go(func() error {
			for name := range deleteChan {
				if err := bucket.Object(name).Delete(ctx); err != nil {
					logger.Error("Failed to delete object", slog.String("name", name), slog.Any("err", err))
				} else {
					logger.Info("Deleted old result", slog.String("name", name))
				}
			}
			return nil
		})
	}

	return gDelete.Wait()
}
