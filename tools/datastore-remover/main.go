package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/datastore"
)

var (
	kind      = flag.String("kind", "", "kind to delete")
	projectID = flag.String("project_id", "", "the gcp project ID")
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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
	if scanner.Text() == "yes" {
		client, _ := datastore.NewClient(ctx, *projectID)

		keys, _ := client.GetAll(ctx, datastore.NewQuery(*kind).KeysOnly(), nil)
		log.Printf("Retrieved %s keys", len(keys))
		for i := 0; i < len(keys); i += 500 {
			fmt.Println("Deleting %d number now", i)
			err := client.DeleteMulti(ctx, keys[i:min(i+500, len(keys))])
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		fmt.Printf("%v\n", len(keys))
	} else {
		fmt.Println("Not yes entered, exiting")
		os.Exit(1)
	}
}
