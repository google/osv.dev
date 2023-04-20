/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"flag"
	"fmt"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/docker/indexer/config"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"

	log "github.com/golang/glog"
	idxStorage "github.com/google/osv.dev/docker/indexer/storage"
)

var (
	configsBucket = flag.String("configs", "", "bucket containing the textproto configs")
	reposBucket   = flag.String("repos", "", "bucket for storing the repository data")
	projectID     = flag.String("project_id", "", "the gcp project ID")
	worker        = flag.Bool("worker", false, "makes this a worker node reading from pubsub to process the data")
	pubsubTopic   = flag.String("topic", "", "sets the pubsub topic to publish to or to read from")
	subName       = flag.String("subscription", "", "sets the pubsub subscription name for workers")
	subMessages   = flag.Int("messages", 1, "pubsub outstanding messages")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	psCl, err := pubsub.NewClient(ctx, *projectID)
	if err != nil {
		log.Exitf("failed to initialize pubsub client: %v", err)
	}
	defer psCl.Close()

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Exitf("failed to initialize storage client: %v", err)
	}
	defer gcsClient.Close()

	repoBucketHdl := gcsClient.Bucket(*reposBucket)

	storer, err := idxStorage.New(ctx, *projectID)
	if err != nil {
		log.Exitf("failed to create the indexers' storer: %v", err)
	}
	defer storer.Close()

	if *worker {
		if err := runWorker(ctx, storer, repoBucketHdl, psCl.Subscription(*subName), *subMessages); err != nil {
			log.Exitf("failed to run worker: %v", err)
		}
		return
	}

	if err := runController(ctx, storer, repoBucketHdl, gcsClient.Bucket(*configsBucket), psCl); err != nil {
		log.Exitf("failed to run controller: %v", err)
	}
}

func runWorker(ctx context.Context, storer *idxStorage.Store, repoBucketHdl *storage.BucketHandle, sub *pubsub.Subscription, outstanding int) error {
	procStage := processing.Stage{
		Storer:                    storer,
		RepoHdl:                   repoBucketHdl,
		Input:                     sub,
		PubSubOutstandingMessages: outstanding,
	}
	// The preparation results are picked up by the processing stage
	// in worker mode.
	// They include checkout options which are used to load the desired
	// repository state and hash the source files in that particular tree.
	// Finally, the computed hashes and repo state information is stored.
	return procStage.Run(ctx)
}

func runController(ctx context.Context, storer *idxStorage.Store, repoBucketHdl, cfgBucketHdl *storage.BucketHandle, psCl *pubsub.Client) error {
	cfgs, err := config.Load(ctx, cfgBucketHdl)
	if err != nil {
		return fmt.Errorf("failed to load configurations: %v", err)
	}

	topic := psCl.Topic(*pubsubTopic)
	defer topic.Stop()

	prepStage := &preparation.Stage{
		Checker: storer,
		RepoHdl: repoBucketHdl,
		Output:  topic,
	}
	// The pipline starts by cloning and/or updating the configured
	// repositories. The results are returned on the procChan channel.
	return prepStage.Run(ctx, cfgs)
}
