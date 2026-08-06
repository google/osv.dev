// Package main implements a CLI tool to sync Repo Consider All Branches (CAB) allowlist YAML files to Cloud Datastore.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"cloud.google.com/go/datastore"
	"gopkg.in/yaml.v3"
)

type RepoCABEntity struct {
	Key   *datastore.Key `yaml:"-" datastore:"__key__"`
	Type  string         `yaml:"type" datastore:"type"`
	Value string         `yaml:"value" datastore:"value"`
}

func main() {
	filePath := flag.String("file", "repo_cab_allowlist.yaml", "Path to repo_cab_allowlist YAML file")
	project := flag.String("project", "oss-vdb-test", "GCP project ID")
	dryRun := flag.Bool("dry-run", true, "Perform dry-run without modifying Datastore")
	verbose := flag.Bool("verbose", false, "Display verbose sync operations")

	flag.Parse()

	if *filePath == "" {
		log.Fatalf("Error: --file argument is required")
	}

	if err := run(context.Background(), *filePath, *project, *dryRun, *verbose); err != nil {
		log.Fatalf("Error syncing repo CAB allowlist: %v", err)
	}
}

func normalizeRepo(repoURL string) string {
	// Normalize the repo_url to align with matching logic
	// Removes the scheme/protocol, the .git extension, and trailing slashes.
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return ""
	}

	if strings.HasPrefix(repoURL, "git@") || strings.HasPrefix(repoURL, "ssh://") {
		log.Printf("Warning: Unsupported SSH URL format %q. Only HTTPS or normalized repository paths are supported.", repoURL)
		return ""
	}

	parsed, err := url.Parse(repoURL)
	if err != nil {
		return repoURL
	}
	normalized := parsed.Host + parsed.Path
	normalized = strings.TrimRight(normalized, "/")
	normalized = strings.TrimSuffix(normalized, ".git")

	return normalized
}

func parseYAMLEntries(data []byte) ([]RepoCABEntity, error) {
	var parsed []RepoCABEntity
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	var entries []RepoCABEntity
	for _, entry := range parsed {
		entry.Type = strings.TrimSpace(strings.ToLower(entry.Type))

		switch entry.Type {
		case "url":
			// For repo URLs, we normalize the value before inserting to datastore
			entry.Value = normalizeRepo(entry.Value)
			if entry.Value == "" {
				continue
			}
		case "regex":
			// For regex, we make sure it compiles
			if entry.Value == "" {
				continue
			}
			if _, err := regexp.Compile(entry.Value); err != nil {
				log.Printf("Warning: Skipping invalid regex pattern %q: %v", entry.Value, err)
				continue
			}
		default:
			log.Printf("Warning: Skipping unrecognized entry type %q for value %q", entry.Type, entry.Value)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func run(ctx context.Context, filePath, project string, dryRun, verbose bool) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading file %s: %w", filePath, err)
	}

	entries, err := parseYAMLEntries(data)
	if err != nil {
		return fmt.Errorf("failed parsing YAML from %s: %w", filePath, err)
	}

	if verbose {
		log.Printf("Loaded %d allowlist entries from %s", len(entries), filePath)
	}

	dsClient, err := datastore.NewClient(ctx, project)
	if err != nil {
		return fmt.Errorf("failed creating datastore client for project %s: %w", project, err)
	}
	defer func() { _ = dsClient.Close() }()

	// Get existing Datastore entities
	query := datastore.NewQuery("RepoConsiderAllBranchesAllowList")
	var dsEntities []RepoCABEntity
	if _, err := dsClient.GetAll(ctx, query, &dsEntities); err != nil {
		return fmt.Errorf("failed fetching existing allowlist entities from datastore: %w", err)
	}

	dsEntitiesMap := make(map[string]RepoCABEntity)
	for _, entity := range dsEntities {
		dsEntitiesMap[entity.Value] = entity
	}

	localEntriesMap := make(map[string]RepoCABEntity)
	for _, item := range entries {
		localEntriesMap[item.Value] = item
	}

	// 1. Put/Upsert entries in local YAML that are not in Datastore or modified
	for val, item := range localEntriesMap {
		existing, exists := dsEntitiesMap[val]
		if !exists {
			key := datastore.IncompleteKey("RepoConsiderAllBranchesAllowList", nil)
			entity := &RepoCABEntity{
				Type:  item.Type,
				Value: item.Value,
			}
			if !dryRun {
				if _, err := dsClient.Put(ctx, key, entity); err != nil {
					return fmt.Errorf("failed putting entity for %s: %w", val, err)
				}
			}
			if verbose {
				log.Printf("Creating RepoConsiderAllBranchesAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
		} else if existing.Type != item.Type {
			entity := &RepoCABEntity{
				Type:  item.Type,
				Value: item.Value,
			}
			if !dryRun {
				if _, err := dsClient.Put(ctx, existing.Key, entity); err != nil {
					return fmt.Errorf("failed updating entity for %s: %w", val, err)
				}
			}
			if verbose {
				log.Printf("Updating RepoConsiderAllBranchesAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
		}
	}

	// 2. Delete entries in Datastore that are no longer in local YAML
	for val, existing := range dsEntitiesMap {
		if _, exists := localEntriesMap[val]; !exists {
			if verbose {
				log.Printf("Deleting RepoConsiderAllBranchesAllowList entity: val=%s", val)
			}
			if !dryRun {
				if err := dsClient.Delete(ctx, existing.Key); err != nil {
					return fmt.Errorf("failed deleting entity for %s: %w", val, err)
				}
			}
		}
	}

	if dryRun {
		log.Println("[DRY RUN] Sync completed successfully.")
	} else {
		log.Println("Sync completed successfully.")
	}
	return nil
}
