package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/logger"
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

	updater := NewUpdater(ctx)

	var wg sync.WaitGroup
	wg.Go(func() { ComputeAliasGroups(ctx, dsClient, updater.Ch) })
	wg.Wait()
	updater.Finish()
}
