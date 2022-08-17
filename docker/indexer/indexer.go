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
)

func main() {
	flag.Parse()

	ctx := context.Background()

	psCl, err := pubsub.NewClient(ctx, *projectID)
	if err != nil {
		log.Exitf("failed to initialize pubsub client: %v", err)
	}
	defer psCl.Close()

	topic := psCl.Topic(*pubsubTopic)
	defer topic.Stop()

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
		sub, err := psCl.CreateSubscription(
			ctx,
			*subName,
			pubsub.SubscriptionConfig{Topic: topic})
		if err != nil {
			log.Exitf("failed to create subscription: %v", err)
			return
		}
		procStage := processing.Stage{
			Storer:  storer,
			RepoHdl: repoBucketHdl,
			Input:   sub,
		}
		// The preparation results are picked up by the processing stage
		// in workder mode.
		// They include checkout options which are used to load the desired
		// repository state and hash the source files in that particular tree.
		// Finally, the computed hashes and repo state information is stored.
		if err := procStage.Run(ctx); err != nil {
			log.Exitf("processing stage failed: %v", err)
		}
		return
	}

	cfgBucketHdl := gcsClient.Bucket(*configsBucket)
	cfgs, err := config.Load(ctx, cfgBucketHdl)
	if err != nil {
		log.Exitf("failed to load configurations: %v", err)
	}

	prepStage := &preparation.Stage{
		Checker: storer,
		RepoHdl: repoBucketHdl,
		Output:  topic,
	}
	// The pipline starts by cloning and/or updating the configured
	// repositories. The results are returned on the procChan channel.
	if err := prepStage.Run(ctx, cfgs); err != nil {
		log.Exitf("preparation stage error %v", err)
	}
}
