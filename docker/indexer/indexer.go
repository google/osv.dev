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

	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	procChan := make(chan *preparation.Result, 10)
	prepGrp := errgroup.Group{}
	prepWg := sync.WaitGroup{}
	prepGrp.SetLimit(2)
	prepStage := preparation.Stage{
		RepoHdl: repoBucketHdl,
		Checker: &idxStorage.Store{},
	}

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
		Storer:  &idxStorage.Store{},
		RepoHdl: repoBucketHdl,
	}

	if err := procStage.Run(stageCtx, procChan); err != nil {
		log.Exitf("processing stage failed: %v", err)
	}

	prepWg.Wait()
}
