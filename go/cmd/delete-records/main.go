package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
)

var (
	projectID   = flag.String("project-id", "", "The GCP project ID")
	bucket      = flag.String("bucket", "", "The GCS bucket for OSV export (e.g. osv-vulnerabilities)")
	file        = flag.String("file", "", "Text file containing record IDs, one per line")
	dryRun      = flag.Bool("dry-run", false, "Do a dry run without deleting anything")
	workerCount = flag.Int("workers", 50, "Number of concurrent workers")
)

func main() {
	flag.Parse()
	if *projectID == "" || *file == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()
	if err := run(ctx); err != nil {
		logger.Error("Command failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	bucketName := *bucket
	if bucketName == "" {
		bucketName = os.Getenv("OSV_VULNERABILITIES_BUCKET")
		if bucketName == "" {
			return errors.New("bucket must be specified via --bucket or OSV_VULNERABILITIES_BUCKET env var")
		}
	}

	recordIDs, err := readRecordIDs(*file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if *dryRun {
		logger.Info("=== DRY RUN MODE ===")
	}
	logger.Info("Loaded records to process", slog.Int("count", len(recordIDs)))

	dsClient, err := datastore.NewClient(ctx, *projectID)
	if err != nil {
		return fmt.Errorf("failed to create datastore client: %w", err)
	}
	defer dsClient.Close()

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer gcsClient.Close()

	bkt := gcsClient.Bucket(bucketName)

	var successCount int32
	var g errgroup.Group
	g.SetLimit(*workerCount)

	for _, id := range recordIDs {

		g.Go(func() error {
			logger.Info("Processing", slog.String("id", id))

			// 1. Delete Datastore entities
			keys := []*datastore.Key{
				datastore.NameKey("Bug", id, nil),
				datastore.NameKey("Vulnerability", id, nil),
				datastore.NameKey("ListedVulnerability", id, nil),
			}

			if *dryRun {
				logger.Info("[DRY-RUN] Would delete Datastore entities", slog.String("id", id))
			} else {
				if err := dsClient.DeleteMulti(ctx, keys); err != nil {
					var multiErr datastore.MultiError
					hasRealError := false

					if errors.As(err, &multiErr) {
						for _, e := range multiErr {
							if e != nil && !errors.Is(e, datastore.ErrNoSuchEntity) {
								hasRealError = true
							}
						}
					} else {
						hasRealError = true
					}

					if hasRealError {
						logger.Error("Failed to delete datastore entities",
							slog.String("id", id),
							slog.Any("error", err))
					} else {
						logger.Info("Deleted (or no-op) Datastore entities", slog.String("id", id))
					}
				} else {
					logger.Info("Deleted Datastore entities", slog.String("id", id))
				}
			}

			// 2. Delete GCS Export
			pbPath := "all/pb/" + id + ".pb"
			if *dryRun {
				logger.Info("[DRY-RUN] Would delete GCS object", slog.String("path", pbPath))
			} else {
				if err := bkt.Object(pbPath).Delete(ctx); err != nil {
					if errors.Is(err, storage.ErrObjectNotExist) {
						logger.Info("Object not found in GCS", slog.String("path", pbPath))
					} else {
						logger.Error("Failed to delete GCS object",
							slog.String("path", pbPath),
							slog.Any("error", err))
					}
				} else {
					logger.Info("Deleted GCS object", slog.String("path", pbPath))
				}
			}

			atomic.AddInt32(&successCount, 1)
			return nil
		})
	}

	// We return nil from inside g.Go, so Wait will never return an error here.
	// This ensures we always process everything, logging errors as we go.
	_ = g.Wait()

	logger.Info("Completed processing",
		slog.Int("processed_successfully", int(successCount)),
		slog.Int("total_records", len(recordIDs)))

	return nil
}

func readRecordIDs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var recordIDs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		id = strings.TrimSuffix(id, ".json")
		if id != "" {
			recordIDs = append(recordIDs, id)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return recordIDs, nil
}
