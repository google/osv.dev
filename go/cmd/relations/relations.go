package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

func main() {
	// Set up logging / other clients
	// Query all Vulnerabilities with raw_aliases, _upstreams or _related
	logger.InitGlobalLogger()
	ctx := context.Background()
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		fmt.Println("GOOGLE_CLOUD_PROJECT not set")
		os.Exit(1)
	}
	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bucketName, ok := os.LookupEnv("OSV_VULNERABILITIES_BUCKET")
	if !ok {
		fmt.Println("OSV_VULNERABILITIES_BUCKET not set")
		os.Exit(1)
	}
	gcsClient := clients.NewGCSClient(storageClient, bucketName)

	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	topicName, ok := os.LookupEnv("OSV_FAILED_TASKS_TOPIC")
	if !ok {
		fmt.Println("OSV_FAILED_TASKS_TOPIC not set")
		os.Exit(1)
	}
	publisher := &clients.GCPPublisher{Publisher: pubsubClient.Publisher(topicName)}

	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
			logger.Error("failed to compute alias groups", slog.Any("err", err))
		}
	}()
	wg.Wait()
	updater.Finish()
}
