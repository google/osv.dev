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
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/docker/indexer/config"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"github.com/google/osv.dev/docker/indexer/stages/processing"
	"golang.org/x/sync/errgroup"

	log "github.com/golang/glog"
	idxStorage "github.com/google/osv.dev/docker/indexer/storage"
)

var (
	configsBucket = flag.String("configs", "", "bucket containing the textproto configs")
	reposBucket   = flag.String("repos", "", "bucket for storing the repository data")
	projectID     = flag.String("project_id", "", "the gcp project ID")
)

func main() {
	flag.Parse()

	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Exitf("failed to initialize storage client: %v", err)
	}
	defer gcsClient.Close()

	cfgBucketHdl := gcsClient.Bucket(*configsBucket)
	repoBucketHdl := gcsClient.Bucket(*reposBucket)

	cfgs, err := config.Load(ctx, cfgBucketHdl)
	if err != nil {
		log.Exitf("failed to load configurations: %v", err)
	}

	storer, err := idxStorage.New(ctx, *projectID)
	if err != nil {
		log.Exitf("failed to create the indexers' storer: %v", err)
	}

	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	procChan := make(chan *preparation.Result, 10)
	prepGrp := errgroup.Group{}
	prepWg := sync.WaitGroup{}
	prepGrp.SetLimit(2)
	prepStage := preparation.Stage{
		RepoHdl: repoBucketHdl,
		Checker: storer,
	}

	// The pipline starts by cloning and/or updating the configured
	// repositories. The results are returned on the procChan channel.
	prepWg.Add(1)
	go func() {
		defer prepWg.Done()
		defer close(procChan)

		err := prepStage.Run(stageCtx, cfgs, procChan)
		if err != nil {
			log.Errorf("preparation stage error: %v", err)
		}
	}()

	procStage := processing.Stage{
		Storer:  storer,
		RepoHdl: repoBucketHdl,
	}

	// The preparation results are picked up by the processing stage.
	// They include checkout options which are used to load the desired
	// repository state and hash the source files in that particular tree.
	// Finally, the computed hashes and repo state information is stored.
	if err := procStage.Run(stageCtx, procChan); err != nil {
		log.Exitf("processing stage failed: %v", err)
	}

	prepWg.Wait()
}
