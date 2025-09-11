package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/models"
)

func main() {
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, os.Getenv("GOOGLE_CLOUD_PROJECT"))
	if err != nil {
		fmt.Printf("(Go) Failed creating Datastore client: %v\n", err)
		os.Exit(1)
	}

	readRecords(ctx, client)
	writeRecords(ctx, client)
}

func readRecords(ctx context.Context, client *datastore.Client) {
	fmt.Println("(Go) Getting Vulnerability")
	key := datastore.NameKey("Vulnerability", "CVE-123-456", nil)
	var vulnerability models.Vulnerability
	if err := client.Get(ctx, key, &vulnerability); err != nil {
		fmt.Printf("(Go) Failed getting Vulnerability: %v\n", err)
		os.Exit(1)
	}
}

func writeRecords(ctx context.Context, client *datastore.Client) {
	fmt.Println("(Go) Writing Vulnerability")
	key := datastore.NameKey("Vulnerability", "CVE-987-654", nil)
	vulnerability := models.Vulnerability{
		SourceID:    "test:path/to/CVE-987-654",
		Modified:    time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC),
		IsWithdrawn: false,
		ModifiedRaw: time.Date(2025, time.December, 1, 23, 59, 59, 0, time.UTC),
		AliasRaw:    []string{"OSV-987-654", "TEST-987-654"},
		RelatedRaw:  []string{"CVE-999-999"},
		UpstreamRaw: []string{"CVE-987-000", "OSV-987-000"},
	}
	if _, err := client.Put(ctx, key, &vulnerability); err != nil {
		fmt.Printf("(Go) Failed writing Vulnerability %v: %v\n", key, err)
		os.Exit(1)
	}
}
