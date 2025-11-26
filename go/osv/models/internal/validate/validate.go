// Package main reads datastore records that were created by the validate.py python script.
// This should not be run outside of the validate.py script.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/osv/models"
)

func main() {
	ctx := context.Background()
	// Note: this does not communicate with GCP.
	// The Python code that runs this sets up the datastore emulator
	// with the relevant environment variables necessary.
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

	fmt.Println("(Go) Getting AliasGroup")
	key = datastore.NameKey("AliasGroup", "1", nil)
	var aliasGroup models.AliasGroup
	if err := client.Get(ctx, key, &aliasGroup); err != nil {
		fmt.Printf("(Go) Failed getting AliasGroup: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("(Go) Getting AliasAllowListEntry")
	key = datastore.NameKey("AliasAllowListEntry", "1", nil)
	var aliasAllowListEntry models.AliasAllowListEntry
	if err := client.Get(ctx, key, &aliasAllowListEntry); err != nil {
		fmt.Printf("(Go) Failed getting AliasAllowListEntry: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("(Go) Getting AliasDenyListEntry")
	key = datastore.NameKey("AliasDenyListEntry", "1", nil)
	var aliasDenyListEntry models.AliasDenyListEntry
	if err := client.Get(ctx, key, &aliasDenyListEntry); err != nil {
		fmt.Printf("(Go) Failed getting AliasDenyListEntry: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("(Go) Getting UpstreamGroup")
	key = datastore.NameKey("UpstreamGroup", "1", nil)
	var upstreamGroup models.UpstreamGroup
	if err := client.Get(ctx, key, &upstreamGroup); err != nil {
		fmt.Printf("(Go) Failed getting UpstreamGroup: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("(Go) Getting ListedVulnerability")
	key = datastore.NameKey("ListedVulnerability", "CVE-123-456", nil)
	var listedVulnerability models.ListedVulnerability
	if err := client.Get(ctx, key, &listedVulnerability); err != nil {
		fmt.Printf("(Go) Failed getting ListedVulnerability: %v\n", err)
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

	fmt.Println("(Go) Writing AliasGroup")
	key = datastore.NameKey("AliasGroup", "2", nil)
	aliasGroup := models.AliasGroup{
		VulnIDs:  []string{"A-1", "B-1", "C-1"},
		Modified: time.Date(2025, time.January, 1, 1, 1, 1, 1, time.UTC),
	}
	if _, err := client.Put(ctx, key, &aliasGroup); err != nil {
		fmt.Printf("(Go) Failed writing AliasGroup %v: %v\n", key, err)
		os.Exit(1)
	}

	fmt.Println("(Go) Writing AliasAllowListEntry")
	key = datastore.NameKey("AliasAllowListEntry", "2", nil)
	aliasAllowListEntry := models.AliasAllowListEntry{
		VulnID: "IS-GOOD",
	}
	if _, err := client.Put(ctx, key, &aliasAllowListEntry); err != nil {
		fmt.Printf("(Go) Failed writing AliasAllowListEntry %v: %v\n", key, err)
		os.Exit(1)
	}

	fmt.Println("(Go) Writing AliasDenyListEntry")
	key = datastore.NameKey("AliasDenyListEntry", "2", nil)
	aliasDenyListEntry := models.AliasDenyListEntry{
		VulnID: "IS-BAD",
	}
	if _, err := client.Put(ctx, key, &aliasDenyListEntry); err != nil {
		fmt.Printf("(Go) Failed writing AliasDenyListEntry %v: %v\n", key, err)
		os.Exit(1)
	}

	fmt.Println("(Go) Writing UpstreamGroup")
	key = datastore.NameKey("UpstreamGroup", "2", nil)
	upstreamGroup := models.UpstreamGroup{
		UpstreamIDs:       []string{"U-1", "U-2"},
		Modified:          time.Date(2025, time.January, 1, 1, 1, 1, 1, time.UTC),
		UpstreamHierarchy: []byte(`{"A": ["B"]}`),
	}
	if _, err := client.Put(ctx, key, &upstreamGroup); err != nil {
		fmt.Printf("(Go) Failed writing UpstreamGroup %v: %v\n", key, err)
		os.Exit(1)
	}

	fmt.Println("(Go) Writing ListedVulnerability")
	key = datastore.NameKey("ListedVulnerability", "CVE-987-654", nil)
	listedVulnerability := models.ListedVulnerability{
		Published:  time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC),
		Ecosystems: []string{"Go", "PyPI"},
		Packages:   []string{"stdlib", "requests"},
		Summary:    "A vulnerability",
		IsFixed:    true,
		Severities: []models.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		AutocompleteTags: []string{"cve-987-654", "stdlib", "requests"},
		SearchIndices:    []string{"cve-987-654", "stdlib", "requests"},
	}
	if _, err := client.Put(ctx, key, &listedVulnerability); err != nil {
		fmt.Printf("(Go) Failed writing ListedVulnerability %v: %v\n", key, err)
		os.Exit(1)
	}
}
