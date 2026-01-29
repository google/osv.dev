package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/models"
	"google.golang.org/api/iterator"
)

func computeRelated(groups map[string][]string, withdrawnVulns map[string]struct{}) map[string][]string {
	// Add the inverse relation of the groups to the map
	for id, group := range groups {
		// We want to prevent withdrawn vulns from being added to related groups.
		// But if a non-withdrawn vuln has a withdrawn vuln as a related id, we want to add it.
		if _, ok := withdrawnVulns[id]; ok {
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

func ComputeRelatedGroups(ctx context.Context, cl *datastore.Client, ch chan<- Update) error {
	// Query for all vulns that have related.
	logger.Info("Retrieving vulns for related computation...")
	q := datastore.NewQuery("Vulnerability").FilterField("related_raw", ">", "")

	rawRelated := make(map[string][]string)
	withdrawnVulns := make(map[string]struct{})
	it := cl.Run(ctx, q)
	for {
		var v models.Vulnerability
		_, err := it.Next(&v)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate vulnerabilities: %w", err)
		}
		if v.IsWithdrawn {
			withdrawnVulns[v.Key.Name] = struct{}{}
		}
		related := slices.Clone(v.RelatedRaw)
		slices.Sort(related)
		related = slices.Compact(related)
		rawRelated[v.Key.Name] = related
	}
	logger.Info("Retrieved vulns with related ids", slog.Int("count", len(rawRelated)))

	logger.Info("Retrieving related groups...")
	q = datastore.NewQuery("RelatedGroup")
	it = cl.Run(ctx, q)
	relatedGroups := make(map[string]models.RelatedGroup)
	for {
		var group models.RelatedGroup
		_, err := it.Next(&group)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate related groups: %w", err)
		}
		relatedGroups[group.Key.Name] = group
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

	for id := range relatedGroups {
		if err := updateRelated(ctx, cl, id, nil, ch); err != nil {
			return fmt.Errorf("failed to delete related group: %w", err)
		}
	}

	return nil
}
