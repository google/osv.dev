package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/sharding"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/models"
)

// computeRelated computes all related groups for the given vulns.
// `groups` is a map of vuln IDs to their related IDs.
// `withdrawnVulns` is a map of withdrawn vulns.
// Returns a map of vuln IDs to their related IDs, with the inverse relation added.
// `groups` is modified in place.
func computeRelated(groups map[string][]string, withdrawnVulns map[string]struct{}) map[string][]string {
	// Add the inverse relation of the groups to the map
	for id, group := range groups {
		if _, ok := withdrawnVulns[id]; ok {
			// We want to prevent withdrawn vulns IDs from being added to related groups,
			// if the withdrawn vuln itself references other non-withdrawn vulns.
			// For example:
			// - If A (withdrawn) relates to B (valid), B should NOT list A.
			// - If A (valid) relates to B (withdrawn), B SHOULD list A.
			continue
		}
		for _, relatedID := range group {
			if _, ok := groups[relatedID]; !ok {
				groups[relatedID] = []string{id}
			} else if !slices.Contains(groups[relatedID], id) {
				groups[relatedID] = append(groups[relatedID], id)
			}
		}
	}

	for _, group := range groups {
		slices.Sort(group)
	}

	return groups
}

func updateVulnWithRelatedGroup(ch chan<- Update, vulnID string, group *models.RelatedGroup, relatedIDs []string) {
	var update Update
	if group == nil {
		update = Update{
			ID:        vulnID,
			Timestamp: time.Now(),
			Field:     updateFieldRelated,
			Value:     relatedIDs,
		}
	} else if !slices.Equal(group.RelatedIDs, relatedIDs) {
		update = Update{
			ID:        vulnID,
			Timestamp: group.Modified,
			Field:     updateFieldRelated,
			Value:     relatedIDs,
		}
	}

	if update.ID != "" {
		ch <- update
	}
}

// ComputeRelatedGroups updates all related groups in the datastore by re-computing existing RelatedGroups
// across key shards.
func ComputeRelatedGroups(ctx context.Context, cl *datastore.Client, ch chan<- Update, keyShards []sharding.KeyShard) error {
	if len(keyShards) == 0 {
		keyShards = []sharding.KeyShard{{Start: "", End: ""}}
	}

	logger.Info("Retrieving vulns for related computation across key shards...")
	rawRelated := make(map[string][]string)
	withdrawnVulns := make(map[string]struct{})
	err := sharding.RunShardedQuery(
		ctx, cl, keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("Vulnerability").FilterField("related_raw", ">", "")

			return sharding.ApplyNameKeyFilter(query, "Vulnerability", shard)
		},
		func(key *datastore.Key, v *models.Vulnerability) {
			if v.IsWithdrawn {
				withdrawnVulns[key.Name] = struct{}{}
			}
			related := slices.Clone(v.RelatedRaw)
			slices.Sort(related)
			rawRelated[key.Name] = slices.Compact(related)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to retrieve raw related vulnerabilities: %w", err)
	}
	logger.Info("Retrieved vulns with related ids", slog.Int("count", len(rawRelated)))

	logger.Info("Retrieving related groups across key shards...")
	relatedGroups := make(map[string]models.RelatedGroup)
	err = sharding.RunShardedQuery(
		ctx, cl, keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("RelatedGroup")

			return sharding.ApplyNameKeyFilter(query, "RelatedGroup", shard)
		},
		func(key *datastore.Key, group *models.RelatedGroup) {
			group.Key = key
			relatedGroups[key.Name] = *group
		},
	)
	if err != nil {
		return fmt.Errorf("failed to retrieve related groups: %w", err)
	}
	logger.Info("Related groups successfully retrieved", slog.Int("count", len(relatedGroups)))

	related := computeRelated(rawRelated, withdrawnVulns)

	for id, relatedIDs := range related {
		g, ok := relatedGroups[id]
		delete(relatedGroups, id)
		var group *models.RelatedGroup
		if ok {
			group = &g
		}
		updateVulnWithRelatedGroup(ch, id, group, relatedIDs)
	}

	// The remaining groups in relatedGroups are the ones that are no longer
	// present in the vulns, so we delete them.
	for id, group := range relatedGroups {
		updateVulnWithRelatedGroup(ch, id, &group, nil)
	}

	return nil
}
