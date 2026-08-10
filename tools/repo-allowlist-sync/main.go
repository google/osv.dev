// Package main implements a CLI tool to sync Repository AllowList YAML files to Cloud Datastore.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"cloud.google.com/go/datastore"
	"go.yaml.in/yaml/v4"
)

const repoAllowListKind = "RepoAllowList"

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

func (r rawYAMLEntry) toEntity() RepoAllowListEntity {
	intro, fixed, limit := false, false, false
	if r.Cherrypicks != nil {
		intro, fixed, limit = *r.Cherrypicks, *r.Cherrypicks, *r.Cherrypicks
	}
	if r.CherrypicksIntroduced != nil {
		intro = *r.CherrypicksIntroduced
	}
	if r.CherrypicksFixed != nil {
		fixed = *r.CherrypicksFixed
	}
	if r.CherrypicksLimit != nil {
		limit = *r.CherrypicksLimit
	}
	return RepoAllowListEntity{
		Type:                  r.Type,
		Value:                 r.Value,
		ConsiderAllBranches:   r.ConsiderAllBranches,
		CherrypicksIntroduced: intro,
		CherrypicksFixed:      fixed,
		CherrypicksLimit:      limit,
	}
}

func (e RepoAllowListEntity) matches(other RepoAllowListEntity) bool {
	return e.Type == other.Type &&
		e.Value == other.Value &&
		e.ConsiderAllBranches == other.ConsiderAllBranches &&
		e.CherrypicksIntroduced == other.CherrypicksIntroduced &&
		e.CherrypicksFixed == other.CherrypicksFixed &&
		e.CherrypicksLimit == other.CherrypicksLimit
}

func repoAllowListKey(val string) *datastore.Key {
	return datastore.NameKey(repoAllowListKind, base64.RawURLEncoding.EncodeToString([]byte(val)), nil)
}

func main() {
	filePath := flag.String("file", "repo_allowlist.yaml", "Path to repo_allowlist YAML file")
	project := flag.String("project", "oss-vdb-test", "GCP project ID")
	dryRun := flag.Bool("dry-run", true, "Perform dry-run without modifying Datastore")
	validate := flag.Bool("validate", false, "Validate YAML configuration file without modifying Datastore")
	verbose := flag.Bool("verbose", true, "Display verbose sync operations")

	flag.Parse()

	if *filePath == "" {
		log.Fatalf("Error: --file argument is required")
	}

	if err := run(context.Background(), *filePath, *project, *dryRun, *validate, *verbose); err != nil {
		log.Fatalf("Error syncing repo allowlist: %v", err)
	}
}

// normalizeRepo removes the URL scheme, trailing slashes, and .git extensions to standardize repo paths.
func normalizeRepo(repoURL string) (string, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return "", fmt.Errorf("repository URL cannot be empty")
	}

	if strings.HasPrefix(repoURL, "git@") || strings.HasPrefix(repoURL, "ssh://") {
		return "", fmt.Errorf("unsupported SSH URL format %q: only HTTPS or normalized repository paths are supported", repoURL)
	}

	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL %q: %w", repoURL, err)
	}
	normalized := parsed.Host + parsed.Path
	normalized = strings.TrimRight(normalized, "/")
	normalized = strings.TrimSuffix(normalized, ".git")

	return normalized, nil
}

// parseYAMLEntries parses and validates allowlist YAML content, expanding shorthand fields and normalizing values.
// If collectAllErrors is true (in validate mode), all entry validation errors are collected and reported together.
// Otherwise, it fails on the first invalid entry.
func parseYAMLEntries(data []byte, collectAllErrors bool) ([]RepoAllowListEntity, error) {
	var rawEntries []rawYAMLEntry
	if err := yaml.Load(data, &rawEntries, yaml.WithKnownFields()); err != nil {
		return nil, fmt.Errorf("failed parsing YAML: %w", err)
	}

	seenValues := make(map[string]int, len(rawEntries))
	entries := make([]RepoAllowListEntity, 0, len(rawEntries))
	var validationErrs []error

	for i, raw := range rawEntries {
		entryNum := i + 1
		raw.Type = strings.TrimSpace(strings.ToLower(raw.Type))

		var entryErr error
		switch raw.Type {
		case "url":
			var err error
			raw.Value, err = normalizeRepo(raw.Value)
			if err != nil {
				entryErr = fmt.Errorf("entry %d: invalid repository URL: %w", entryNum, err)
			}
		case "regex":
			if raw.Value == "" {
				entryErr = fmt.Errorf("entry %d: empty regex pattern", entryNum)
			} else if _, err := regexp.Compile(raw.Value); err != nil {
				entryErr = fmt.Errorf("entry %d: invalid regex pattern %q: %w", entryNum, raw.Value, err)
			}
		default:
			entryErr = fmt.Errorf("entry %d: unrecognized entry type %q for value %q", entryNum, raw.Type, raw.Value)
		}

		if entryErr == nil && raw.Value != "" {
			if prevIdx, seen := seenValues[raw.Value]; seen {
				entryErr = fmt.Errorf("entry %d: duplicate allowlist entry value %q (previously seen at entry %d)", entryNum, raw.Value, prevIdx)
			} else {
				seenValues[raw.Value] = entryNum
			}
		}

		if entryErr != nil {
			if !collectAllErrors {
				return nil, entryErr
			}
			validationErrs = append(validationErrs, entryErr)
			continue
		}

		entries = append(entries, raw.toEntity())
	}

	if len(validationErrs) > 0 {
		return nil, errors.Join(validationErrs...)
	}

	return entries, nil
}

func run(ctx context.Context, filePath, project string, dryRun, validate, verbose bool) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading file %s: %w", filePath, err)
	}

	entries, err := parseYAMLEntries(data, validate)
	if err != nil {
		return fmt.Errorf("failed parsing YAML from %s: %w", filePath, err)
	}

	if validate {
		log.Printf("[VALIDATE] YAML file %s is valid. Found %d total entries.", filePath, len(entries))
		return nil
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
	query := datastore.NewQuery(repoAllowListKind)
	var dsEntities []RepoAllowListEntity
	if _, err := dsClient.GetAll(ctx, query, &dsEntities); err != nil {
		return fmt.Errorf("failed fetching existing allowlist entities from datastore: %w", err)
	}

	dsEntitiesMap := make(map[string]RepoAllowListEntity, len(dsEntities))
	for _, entity := range dsEntities {
		dsEntitiesMap[entity.Value] = entity
	}

	localEntriesMap := make(map[string]RepoAllowListEntity, len(entries))
	for _, item := range entries {
		localEntriesMap[item.Value] = item
	}

	var createdCount, updatedCount, deletedCount, unchangedCount int

	// Upsert entries in local YAML that are missing from Datastore or modified
	for val, item := range localEntriesMap {
		existing, exists := dsEntitiesMap[val]
		entity := item

		if !exists {
			createdCount++
			if verbose {
				log.Printf("Creating RepoAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
			key := repoAllowListKey(val)
			if !dryRun {
				if _, err := dsClient.Put(ctx, key, &entity); err != nil {
					return fmt.Errorf("failed putting entity for %s: %w", val, err)
				}
			}
		} else if !existing.matches(item) {
			updatedCount++
			if verbose {
				log.Printf("Updating RepoAllowList entity: type=%s val=%s", item.Type, item.Value)
			}
			entity.Key = existing.Key
			if !dryRun {
				if _, err := dsClient.Put(ctx, existing.Key, &entity); err != nil {
					return fmt.Errorf("failed updating entity for %s: %w", val, err)
				}
			}
		} else {
			unchangedCount++
		}
	}

	// Delete entries in Datastore that are no longer present in local YAML
	for val, existing := range dsEntitiesMap {
		if _, exists := localEntriesMap[val]; !exists {
			deletedCount++
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

	mode := "LIVE"
	if dryRun {
		mode = "DRY RUN"
	}
	log.Printf("[%s] Sync completed: %d created, %d updated, %d deleted, %d unchanged.", mode, createdCount, updatedCount, deletedCount, unchangedCount)

	return nil
}
