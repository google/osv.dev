// osv-linter-worker
//
// # Worker for osv-linter
//
// This worker is responsible for running osv-linter and uploading the results to GCS.
// It also writes the results to Datastore.
//
// Usage:
//
//	go run main.go -work-dir=/tmp -local-data=/path/to/all.zip -linter-bin=osv-linter -dry-run=true
//
// Options:
//
//	work-dir: Working directory
//	local-data: Path to local all.zip or directory containing OSV data
//	linter-bin: Path to osv-linter binary
//	dry-run: Dry run mode (no GCS upload or Datastore writes)
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
	db "github.com/google/osv.dev/go/internal/database/datastore"
	internalmodels "github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
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

var errorCodeMapping = map[string]internalmodels.ImportFindings{
	"SCH:001": internalmodels.ImportFindingsInvalidJSON,
	"REC:001": internalmodels.ImportFindingsInvalidRecord,
	"REC:002": internalmodels.ImportFindingsInvalidAliases,
	"REC:003": internalmodels.ImportFindingsInvalidUpstream,
	"REC:004": internalmodels.ImportFindingsInvalidRelated,
	"RNG:001": internalmodels.ImportFindingsInvalidRange,
	"RNG:002": internalmodels.ImportFindingsInvalidRange,
	"PKG:001": internalmodels.ImportFindingsInvalidPackage,
	"PKG:002": internalmodels.ImportFindingsInvalidVersion,
	"PKG:003": internalmodels.ImportFindingsInvalidPURL,
}

var (
	workDir      = flag.String("work-dir", "tmp", "Working directory")
	localData    = flag.String("local-data", "", "Path to local all.zip or directory containing OSV data")
	linterBinary = flag.String("linter-bin", "osv-linter", "Path to osv-linter binary")
	dryRun       = flag.Bool("dry-run", true, "Dry run mode (no GCS upload or Datastore writes)")
)

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()
	flag.Parse()
	if err := run(); err != nil {
		logger.Fatal("error running linter worker", slog.Any("err", err))
	}
}

func run() error {
	ctx := context.Background()
	dsClient, err := datastore.NewClient(ctx, gcpProject)
	if err != nil {
		return fmt.Errorf("failed to create datastore client: %w", err)
	}
	defer dsClient.Close()

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}
	defer storageClient.Close()

	sourceRepoStore := db.NewSourceRepositoryStore(dsClient)
	importFindingsStore := db.NewImportFindingsStore(dsClient, storageClient, linterExportBucket, linterResultDir)

	prefixToSource, err := constructPrefixToSourceMap(ctx, sourceRepoStore)
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

	if err := processLinterResult(ctx, importFindingsStore, linterOutput, prefixToSource, *dryRun); err != nil {
		return fmt.Errorf("failed to process linter result: %w", err)
	}

	return nil
}

func constructPrefixToSourceMap(ctx context.Context, store internalmodels.SourceRepositoryStore) (map[string]string, error) {
	prefixToSource := make(map[string]string)
	for source, err := range store.All(ctx) {
		if err != nil {
			return nil, err
		}
		for _, prefix := range source.IDPrefixes {
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
			hasJSON := false
			err := filepath.WalkDir(localData, func(_ string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && filepath.Ext(d.Name()) == ".json" {
					hasJSON = true
					return filepath.SkipAll
				}

				return nil
			})
			if err != nil {
				return "", fmt.Errorf("failed to walk data dir: %w", err)
			}
			if !hasJSON {
				if _, err := os.Stat(filepath.Join(localData, zipFilePath)); err == nil {
					logger.Warn("Directory contains no JSON files but contains all.zip. Did you forget to unzip it?", slog.String("dir", localData))
				}
			}

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

func processLinterResult(ctx context.Context, store internalmodels.ImportFindingsStore, output []byte, prefixToSource map[string]string, dryRun bool) error {
	var results map[string][]map[string]any
	if len(output) == 0 {
		return errors.New("linter output is empty")
	}
	if err := json.Unmarshal(output, &results); err != nil {
		return fmt.Errorf("failed to parse linter output: %w", err)
	}

	logger.Info("Successfully parsed linter output")

	g, groupCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := uploadRecordToStore(groupCtx, store, results, prefixToSource, dryRun); err != nil {
			logger.Error("Failed to upload results to store", slog.Any("err", err))
			return nil
		}

		return nil
	})

	// 2. Fetch existing findings (Async)
	existingIDs := make(map[string]bool)
	g.Go(func() error {
		ids, err := store.ListIDs(groupCtx)
		if err != nil {
			return fmt.Errorf("failed to fetch existing findings: %w", err)
		}
		for _, id := range ids {
			existingIDs[id] = true
		}

		return nil
	})

	// 3. Process findings and update Datastore (Parallel)
	linterBugs := make(map[string]bool)
	findingsToPut := make([]*internalmodels.ImportFinding, 0, len(results))
	now := time.Now().UTC()

	// Prepare findings in memory first (CPU bound)
	for filename, findingsList := range results {
		bugID := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		linterBugs[bugID] = true

		if len(findingsList) == 0 {
			continue
		}

		uniqueFindings := make(map[internalmodels.ImportFindings]bool)
		for _, f := range findingsList {
			code, ok := f["Code"].(string)
			if !ok {
				code = "UNKNOWN_CODE"
			}
			importFinding := errorCodeMapping[code]
			if importFinding == 0 {
				importFinding = internalmodels.ImportFindingsNone
			}
			uniqueFindings[importFinding] = true
		}

		var sortedFindings []internalmodels.ImportFindings
		for f := range uniqueFindings {
			sortedFindings = append(sortedFindings, f)
		}
		sort.Slice(sortedFindings, func(i, j int) bool {
			return sortedFindings[i] < sortedFindings[j]
		})

		prefix := strings.Split(bugID, "-")[0] + "-"
		source := prefixToSource[prefix]

		finding := &internalmodels.ImportFinding{
			BugID:       bugID,
			Source:      source,
			Findings:    sortedFindings,
			LastAttempt: now,
		}
		findingsToPut = append(findingsToPut, finding)
	}

	// Launch workers to process findingsToPut

	// Create a channel for batches
	batchChan := make(chan []*internalmodels.ImportFinding, len(findingsToPut)/batchSize+1)

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
				if err := processBatch(groupCtx, store, batch, now, &updatedCount, dryRun); err != nil {
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

	var idsToDelete []string
	for id := range existingIDs {
		if !linterBugs[id] {
			idsToDelete = append(idsToDelete, id)
			logger.Debug("Deleting stale finding", slog.String("bugID", id))
		}
	}

	if len(idsToDelete) > 0 {
		if dryRun {
			logger.Info("Dry run: skipping deletion of stale findings", slog.Int("count", len(idsToDelete)))
		} else {
			// Delete in batches
			deleteG, deleteCtx := errgroup.WithContext(ctx)
			deleteBatchChan := make(chan []string, len(idsToDelete)/batchSize+1)

			for i := 0; i < len(idsToDelete); i += batchSize {
				end := i + batchSize
				if end > len(idsToDelete) {
					end = len(idsToDelete)
				}
				deleteBatchChan <- idsToDelete[i:end]
			}
			close(deleteBatchChan)

			for range maxConcurrency {
				deleteG.Go(func() error {
					for batch := range deleteBatchChan {
						if err := store.DeleteMulti(deleteCtx, batch); err != nil {
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

func processBatch(ctx context.Context, store internalmodels.ImportFindingsStore, batch []*internalmodels.ImportFinding, now time.Time, updatedCount *int64, dryRun bool) error {
	bugIDs := make([]string, len(batch))
	for j, f := range batch {
		bugIDs[j] = f.BugID
	}

	existing, err := store.GetMulti(ctx, bugIDs)
	if err != nil {
		return err
	}

	for j, f := range batch {
		if f == nil {
			continue
		}
		if existing[j] == nil {
			batch[j].FirstSeen = now
			logger.Info("New finding", slog.String("bugID", batch[j].BugID))
		} else {
			batch[j].FirstSeen = existing[j].FirstSeen
			if equalFindings(batch[j].Findings, existing[j].Findings) {
				batch[j] = nil // Skip
			}
		}
	}

	var cleanBatch []*internalmodels.ImportFinding
	for _, f := range batch {
		if f != nil {
			cleanBatch = append(cleanBatch, f)
		}
	}

	if len(cleanBatch) > 0 {
		if dryRun {
			logger.Info("Dry run: skipping put of findings", slog.Int("count", len(cleanBatch)))
		} else {
			if err := store.PutMulti(ctx, cleanBatch); err != nil {
				return err
			}
		}
		atomic.AddInt64(updatedCount, int64(len(cleanBatch)))
	}

	return nil
}

func equalFindings(a, b []internalmodels.ImportFindings) bool {
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

func uploadRecordToStore(ctx context.Context, store internalmodels.ImportFindingsStore, results map[string][]map[string]any, prefixToSource map[string]string, dryRun bool) error {
	existingObjects, err := store.ListResultSources(ctx)
	if err != nil {
		return err
	}
	existingObjectsMap := make(map[string]bool)
	for _, obj := range existingObjects {
		existingObjectsMap[obj] = true
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
	gUpload, uploadCtx := errgroup.WithContext(ctx)
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
				if dryRun {
					logger.Info("Dry run: skipping upload", slog.String("source", task.source))
					continue
				}

				if err := store.UploadResult(uploadCtx, task.source, task.data); err != nil {
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
	for objName := range existingObjectsMap {
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
	gDelete, deleteCtx := errgroup.WithContext(ctx)
	deleteChan := make(chan string, len(toDelete))
	for _, name := range toDelete {
		deleteChan <- name
	}
	close(deleteChan)

	for range maxConcurrency {
		gDelete.Go(func() error {
			for name := range deleteChan {
				if err := store.DeleteResult(deleteCtx, name); err != nil {
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
