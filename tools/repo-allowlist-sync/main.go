// Package main implements a CLI tool to sync Repository AllowList YAML files to Cloud Datastore.
package main

import (
	"context"
	"encoding/base64"
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

// TODO: Use go model RepoAllowList struct (#5797)
// RepoAllowListEntity represents a repository allowlist entity stored in Cloud Datastore
type RepoAllowListEntity struct {
	Key                   *datastore.Key `datastore:"__key__"`
	Type                  string         `datastore:"type"`
	Value                 string         `datastore:"value"`
	ConsiderAllBranches   bool           `datastore:"consider_all_branches"`
	CherrypicksIntroduced bool           `datastore:"cherrypicks_introduced"`
	CherrypicksFixed      bool           `datastore:"cherrypicks_fixed"`
	CherrypicksLimit      bool           `datastore:"cherrypicks_limit"`
}

// rawYAMLEntry represents an unmarshaled entry from the YAML file, including optional shorthand field
type rawYAMLEntry struct {
	Type                  string `yaml:"type"`
	Value                 string `yaml:"value"`
	ConsiderAllBranches   bool   `yaml:"consider_all_branches"`
	Cherrypicks           *bool  `yaml:"cherrypicks"`
	CherrypicksIntroduced *bool  `yaml:"cherrypicks_introduced"`
	CherrypicksFixed      *bool  `yaml:"cherrypicks_fixed"`
	CherrypicksLimit      *bool  `yaml:"cherrypicks_limit"`
}

func (e RepoAllowListEntity) matches(other RepoAllowListEntity) bool {
	return e.Type == other.Type &&
		e.Value == other.Value &&
		e.ConsiderAllBranches == other.ConsiderAllBranches &&
		e.CherrypicksIntroduced == other.CherrypicksIntroduced &&
		e.CherrypicksFixed == other.CherrypicksFixed &&
		e.CherrypicksLimit == other.CherrypicksLimit
}

func main() {
	filePath := flag.String("file", "repo_allowlist.yaml", "Path to repo_allowlist YAML file")
	project := flag.String("project", "oss-vdb-test", "GCP project ID")
	dryRun := flag.Bool("dry-run", true, "Perform dry-run without modifying Datastore")
	verbose := flag.Bool("verbose", false, "Display verbose sync operations")

	flag.Parse()

	if *filePath == "" {
		log.Fatalf("Error: --file argument is required")
	}

	if err := run(context.Background(), *filePath, *project, *dryRun, *verbose); err != nil {
		log.Fatalf("Error syncing repo allowlist: %v", err)
	}
}

// normalizeRepo removes the URL scheme, trailing slashes, and .git extensions to standardize repo paths.
func normalizeRepo(repoURL string) string {
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

// parseYAMLEntries parses and validates allowlist YAML content, expanding shorthand fields and normalizing values.
func parseYAMLEntries(data []byte) ([]RepoAllowListEntity, error) {
	var rawEntries []rawYAMLEntry
	if err := yaml.Unmarshal(data, &rawEntries); err != nil {
		return nil, err
	}

	var entries []RepoAllowListEntity
	for _, raw := range rawEntries {
		raw.Type = strings.TrimSpace(strings.ToLower(raw.Type))

		switch raw.Type {
		case "url":
			raw.Value = normalizeRepo(raw.Value)
			if raw.Value == "" {
				continue
			}
		case "regex":
			if raw.Value == "" {
				continue
			}
			if _, err := regexp.Compile(raw.Value); err != nil {
				log.Printf("Warning: Skipping invalid regex pattern %q: %v", raw.Value, err)
				continue
			}
		default:
			log.Printf("Warning: Skipping unrecognized entry type %q for value %q", raw.Type, raw.Value)
			continue
		}

		// Process cherrypicks flags: "cherrypicks: bool" acts as a shorthand for all 3 event types,
		// specifying "cherrypicks_<event>" fields overrides that.
		intro := false
		fixed := false
		limit := false

		if raw.Cherrypicks != nil {
			intro = *raw.Cherrypicks
			fixed = *raw.Cherrypicks
			limit = *raw.Cherrypicks
		}
		if raw.CherrypicksIntroduced != nil {
			intro = *raw.CherrypicksIntroduced
		}
		if raw.CherrypicksFixed != nil {
			fixed = *raw.CherrypicksFixed
		}
		if raw.CherrypicksLimit != nil {
			limit = *raw.CherrypicksLimit
		}

		entries = append(entries, RepoAllowListEntity{
			Type:                  raw.Type,
			Value:                 raw.Value,
			ConsiderAllBranches:   raw.ConsiderAllBranches,
			CherrypicksIntroduced: intro,
			CherrypicksFixed:      fixed,
			CherrypicksLimit:      limit,
		})
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

	// Fetch existing Datastore entities
	query := datastore.NewQuery("RepoAllowList")
	var dsEntities []RepoAllowListEntity
	if _, err := dsClient.GetAll(ctx, query, &dsEntities); err != nil {
		return fmt.Errorf("failed fetching existing allowlist entities from datastore: %w", err)
	}

	dsEntitiesMap := make(map[string]RepoAllowListEntity)
	for _, entity := range dsEntities {
		dsEntitiesMap[entity.Value] = entity
	}

	localEntriesMap := make(map[string]RepoAllowListEntity)
	for _, item := range entries {
		localEntriesMap[item.Value] = item
	}

	// Upsert entries in local YAML that are missing from Datastore or modified
	for val, item := range localEntriesMap {
		existing, exists := dsEntitiesMap[val]
		entity := &RepoAllowListEntity{
			Type:                  item.Type,
			Value:                 item.Value,
			ConsiderAllBranches:   item.ConsiderAllBranches,
			CherrypicksIntroduced: item.CherrypicksIntroduced,
			CherrypicksFixed:      item.CherrypicksFixed,
			CherrypicksLimit:      item.CherrypicksLimit,
		}

		if !exists {
			key := datastore.NameKey("RepoAllowList", base64.RawURLEncoding.EncodeToString([]byte(val)), nil)
			if !dryRun {
				if _, err := dsClient.Put(ctx, key, entity); err != nil {
					return fmt.Errorf("failed putting entity for %s: %w", val, err)
				}
			}
			if verbose {
				log.Printf("Creating RepoAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
		} else if !existing.matches(item) {
			entity.Key = existing.Key
			if !dryRun {
				if _, err := dsClient.Put(ctx, existing.Key, entity); err != nil {
					return fmt.Errorf("failed updating entity for %s: %w", val, err)
				}
			}
			if verbose {
				log.Printf("Updating RepoAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
		}
	}

	// Delete entries in Datastore that are no longer present in local YAML
	for val, existing := range dsEntitiesMap {
		if _, exists := localEntriesMap[val]; !exists {
			if verbose {
				log.Printf("Deleting RepoAllowList entity: val=%s", val)
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
