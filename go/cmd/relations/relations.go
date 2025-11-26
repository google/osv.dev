// Copyright 2025 Google LLC
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

// Package main runs the vulnerability relations computation job.
package main

import (
	"context"
	"errors"
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

type gClients struct {
	datastoreClient *datastore.Client
	gcsClient       *clients.GCSClient
	publisher       clients.Publisher
	closeAll        func()
}

func main() {
	// Set up logging / other clients
	logger.InitGlobalLogger()
	ctx := context.Background()
	gc, err := setupClients(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer gc.closeAll()

	updater := NewUpdater(ctx, gc.datastoreClient, gc.gcsClient, gc.publisher)

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := ComputeAliasGroups(ctx, gc.datastoreClient, updater.Ch); err != nil {
			logger.Error("failed to compute alias groups", slog.Any("err", err))
		}
	})
	wg.Go(func() {
		if err := ComputeUpstreamGroups(ctx, gc.datastoreClient, updater.Ch); err != nil {
			logger.Error("failed to compute upstream groups", slog.Any("err", err))
		}
	})
	wg.Wait()
	updater.Finish()
}

func setupClients(ctx context.Context) (gClients, error) {
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		return gClients{}, errors.New("GOOGLE_CLOUD_PROJECT not set")
	}
	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return gClients{}, fmt.Errorf("failed to create datastore client: %w", err)
	}

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return gClients{}, fmt.Errorf("failed to create storage client: %w", err)
	}
	bucketName, ok := os.LookupEnv("OSV_VULNERABILITIES_BUCKET")
	if !ok {
		storageClient.Close()
		return gClients{}, errors.New("OSV_VULNERABILITIES_BUCKET not set")
	}
	gcsClient := clients.NewGCSClient(storageClient, bucketName)

	pubsubClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		gcsClient.Close()
		return gClients{}, fmt.Errorf("failed to create pubsub client: %w", err)
	}

	topicName, ok := os.LookupEnv("OSV_FAILED_TASKS_TOPIC")
	if !ok {
		gcsClient.Close()
		pubsubClient.Close()

		return gClients{}, errors.New("OSV_FAILED_TASKS_TOPIC not set")
	}
	publisher := &clients.GCPPublisher{Publisher: pubsubClient.Publisher(topicName)}

	closeAll := func() {
		dsClient.Close()
		gcsClient.Close()
		pubsubClient.Close()
	}

	return gClients{
		datastoreClient: dsClient,
		gcsClient:       gcsClient,
		publisher:       publisher,
		closeAll:        closeAll,
	}, nil
}
