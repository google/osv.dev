package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"cloud.google.com/go/datastore"
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
		for _, related := range group {
			if slices.Contains(groups[related], id) {
				continue
			}
			groups[related] = append(groups[related], id)
			slices.Sort(groups[related])
		}
	}

	return groups
}

func updateRelated(ctx context.Context, cl *datastore.Client, id string, relatedIDs []string, ch chan<- Update) error {
	if len(relatedIDs) == 0 {
		logger.Info("Deleting related group due to no related vulns", slog.String("id", id))
		if err := cl.Delete(ctx, datastore.NameKey("RelatedGroup", id, nil)); err != nil {
			return err
		}
		ch <- Update{
			ID:        id,
			Timestamp: time.Now().UTC(),
			Field:     updateFieldRelated,
			Value:     nil,
		}

		return nil
	}

	group := models.RelatedGroup{
		RelatedIDs: relatedIDs,
		Modified:   time.Now().UTC(),
	}
	if _, err := cl.Put(ctx, datastore.NameKey("RelatedGroup", id, nil), &group); err != nil {
		return err
	}
	ch <- Update{
		ID:        id,
		Timestamp: group.Modified,
		Field:     updateFieldRelated,
		Value:     relatedIDs,
	}

	return nil
}

// ComputeRelatedGroups updates all related groups in the datastore by re-computing existing RelatedGroups
// across key shards.
func ComputeRelatedGroups(ctx context.Context, cl *datastore.Client, ch chan<- Update, keyShards []KeyShard) error {
	if len(keyShards) == 0 {
		keyShards = []KeyShard{{Start: "", End: ""}}
	}

	logger.Info("Retrieving vulns for related computation across key shards...")
	rawRelated := make(map[string][]string)
	withdrawnVulns := make(map[string]struct{})
	err := runShardedQuery(
		ctx, cl, keyShards,
		func(shard KeyShard) *datastore.Query {
			query := datastore.NewQuery("Vulnerability").FilterField("related_raw", ">", "")

			return applyNameKeyFilter(query, "Vulnerability", shard)
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
	err = runShardedQuery(
		ctx, cl, keyShards,
		func(shard KeyShard) *datastore.Query {
			query := datastore.NewQuery("RelatedGroup")

			return applyNameKeyFilter(query, "RelatedGroup", shard)
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
		if !ok || !slices.Equal(g.RelatedIDs, relatedIDs) {
			if err := updateRelated(ctx, cl, id, relatedIDs, ch); err != nil {
				return fmt.Errorf("failed to update related group: %w", err)
			}
		}
	}

	// The remaining groups in relatedGroups are the ones that are no longer
	// present in the vulns, so we delete them.
	for id := range relatedGroups {
		if err := updateRelated(ctx, cl, id, nil, ch); err != nil {
			return fmt.Errorf("failed to delete related group: %w", err)
		}
	}

	return nil
}
