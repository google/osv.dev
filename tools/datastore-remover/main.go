package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/datastore"
	"google.golang.org/api/iterator"
)

var (
	kind       = flag.String("kind", "", "kind to delete")
	projectID  = flag.String("project_id", "", "the gcp project ID")
	batchSize  = flag.Int("batch_size", 500, "batch size for deletions")
	waitTimeMS = flag.Int("wait_ms", 500, "wait time in between batch deletions")
	total      = 0
)

func main() {
	flag.Parse()
	if *kind == "" || *projectID == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Deleting kind: %s, in project: %s\nEnter yes to confirm: \n", *kind, *projectID)
	scanner.Scan()
	if scanner.Text() != "yes" {
		fmt.Println("Not yes entered, exiting")
		os.Exit(1)
	}

	client, _ := datastore.NewClient(ctx, *projectID)
	it := client.Run(ctx, datastore.NewQuery(*kind).KeysOnly())

	var batch []*datastore.Key
	for {
		key, err := it.Next(nil)
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("%v", err)
		}
		batch = append(batch, key)

		if len(batch) >= *batchSize {
			deleteBatch(ctx, client, batch)
			batch = nil
		}
	}

	if len(batch) > 0 {
		deleteBatch(ctx, client, batch)
		batch = nil
	}
}

func deleteBatch(ctx context.Context, client *datastore.Client, keys []*datastore.Key) {
	err := client.DeleteMulti(ctx, keys)
	if err != nil {
		log.Fatalf("%v", err)
	}
	total += len(keys)
	if total%(*batchSize*10) == 0 {
		log.Printf("Deleted %d.\n", total)
	}
	time.Sleep(time.Duration(*waitTimeMS) * time.Millisecond)
}
