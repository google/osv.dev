package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
)

var (
	projectID = flag.String("project-id", "", "The GCP project ID")
	bucket    = flag.String("bucket", "", "The GCS bucket for OSV export (e.g. osv-vulnerabilities)")
	file      = flag.String("file", "", "Text file containing record IDs, one per line")
	dryRun    = flag.Bool("dry-run", false, "Do a dry run without deleting anything")
)

func main() {
	flag.Parse()
	if *projectID == "" || *file == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	bucketName := *bucket
	if bucketName == "" {
		bucketName = os.Getenv("OSV_VULNERABILITIES_BUCKET")
		if bucketName == "" {
			log.Fatalf("Bucket must be specified via --bucket or OSV_VULNERABILITIES_BUCKET env var")
		}
	}

	f, err := os.Open(*file)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	var recordIDs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		id := scanner.Text()
		id = strings.TrimSuffix(id, ".json")
		if id != "" {
			recordIDs = append(recordIDs, id)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	if *dryRun {
		fmt.Println("=== DRY RUN MODE ===")
	}
	fmt.Printf("Loaded %d records to process.\n", len(recordIDs))

	ctx := context.Background()

	dsClient, err := datastore.NewClient(ctx, *projectID)
	if err != nil {
		log.Fatalf("Failed to create datastore client: %v", err)
	}
	defer dsClient.Close()

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create GCS client: %v", err)
	}
	defer gcsClient.Close()

	bkt := gcsClient.Bucket(bucketName)

	successCount := 0
	for _, id := range recordIDs {
		fmt.Printf("Processing %s...\n", id)

		// 1. Delete Datastore entities
		bugKey := datastore.NameKey("Bug", id, nil)
		vulnKey := datastore.NameKey("Vulnerability", id, nil)
		keys := []*datastore.Key{bugKey, vulnKey}

		if *dryRun {
			fmt.Printf("  [DRY-RUN] Would delete Datastore entities: Bug/%s, Vulnerability/%s\n", id, id)
		} else {
			err := dsClient.DeleteMulti(ctx, keys)
			if err != nil {
				if multiErr, ok := err.(datastore.MultiError); ok {
					hasRealError := false
					for _, e := range multiErr {
						if e != nil && e != datastore.ErrNoSuchEntity {
							log.Printf("  Datastore delete error: %v", e)
							hasRealError = true
						}
					}
					if !hasRealError {
						fmt.Printf("  Deleted (or no-op) Datastore entities for %s.\n", id)
					}
				} else {
					log.Printf("  Failed to delete datastore entities: %v", err)
				}
			} else {
				fmt.Printf("  Deleted Datastore entities for %s.\n", id)
			}
		}

		// 2. Delete GCS Export
		pbPath := "all/pb/" + id + ".pb"
		obj := bkt.Object(pbPath)
		if *dryRun {
			fmt.Printf("  [DRY-RUN] Would delete GCS object: gs://%s/%s\n", bucketName, pbPath)
		} else {
			if err := obj.Delete(ctx); err != nil {
				if err == storage.ErrObjectNotExist {
					fmt.Printf("  Object gs://%s/%s not found in GCS.\n", bucketName, pbPath)
				} else {
					log.Printf("  Failed to delete GCS object %s: %v", pbPath, err)
				}
			} else {
				fmt.Printf("  Deleted gs://%s/%s\n", bucketName, pbPath)
			}
		}
		successCount++
	}

	fmt.Printf("\nCompleted. Processed %d/%d records.\n", successCount, len(recordIDs))
}
