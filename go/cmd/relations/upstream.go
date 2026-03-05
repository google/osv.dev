// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

// computeUpstream computes all upstream vulnerabilities for the given vuln ID.
// The returned slice contains all of the vuln IDs that are upstream of the
// target vuln ID, including transitive upstreams.
func computeUpstream(vulnID string, rawUpstreams map[string][]string) []string {
	visited := make(map[string]struct{})
	toVisit := slices.Clone(rawUpstreams[vulnID])

	var result []string
	for len(toVisit) > 0 {
		vulnID := toVisit[0]
		toVisit = toVisit[1:]

		if _, ok := visited[vulnID]; ok {
			continue
		}
		visited[vulnID] = struct{}{}
		result = append(result, vulnID)

		if upstreams, ok := rawUpstreams[vulnID]; ok {
			for _, upstream := range upstreams {
				if _, ok := visited[upstream]; !ok {
					toVisit = append(toVisit, upstream)
				}
			}
		}
	}
	slices.Sort(result)

	return result
}

// createUpstreamGroup creates a new upstream group in the datastore and sends it to the updater.
func createUpstreamGroup(ctx context.Context, cl *datastore.Client, vulnID string, upstreamIDs []string, ch chan<- Update) (*models.UpstreamGroup, error) {
	key := datastore.IncompleteKey("UpstreamGroup", nil)
	group := &models.UpstreamGroup{
		VulnID:      vulnID,
		UpstreamIDs: upstreamIDs,
		Modified:    time.Now().UTC(),
	}
	var err error
	if key, err = cl.Put(ctx, key, group); err != nil {
		return nil, err
	}
	group.Key = key
	updateVulnWithUpstream(ch, vulnID, group)

	return group, nil
}

// updateUpstreamGroup updates the upstream group in the datastore, and sends it to the updater.
func updateUpstreamGroup(ctx context.Context, cl *datastore.Client, group *models.UpstreamGroup, upstreamIDs []string, ch chan<- Update) (*models.UpstreamGroup, error) {
	if len(upstreamIDs) == 0 {
		logger.Info("Deleting upstream group due to no upstream vulns", slog.String("id", group.VulnID))
		if err := cl.Delete(ctx, group.Key); err != nil {
			return nil, err
		}
		updateVulnWithUpstream(ch, group.VulnID, nil)

		return nil, nil //nolint:nilnil
	}

	if slices.Equal(upstreamIDs, group.UpstreamIDs) {
		return nil, nil //nolint:nilnil
	}

	group.UpstreamIDs = upstreamIDs
	group.Modified = time.Now().UTC()
	if _, err := cl.Put(ctx, group.Key, group); err != nil {
		return nil, err
	}
	updateVulnWithUpstream(ch, group.VulnID, group)

	return group, nil
}

// updateVulnWithUpstream sends an update for the vuln in Datastore & GCS with the new upstream group.
// If group is nil, assumes a preexisting UpstreamGroup was just deleted.
func updateVulnWithUpstream(ch chan<- Update, vulnID string, group *models.UpstreamGroup) {
	update := Update{ID: vulnID, Field: updateFieldUpstream}
	if group == nil { // group was deleted
		update.Timestamp = time.Now().UTC()
		update.Value = nil
	} else {
		update.Timestamp = group.Modified
		update.Value = group.UpstreamIDs
	}
	ch <- update
}

// computeUpstreamHierarchy computes all upstream vulnerabilities for the given vuln ID.
// It puts into Datastore a list containing all of the vuln IDs that are upstream of the target vuln ID,
// including transitive upstreams in a map hierarchy.
// UpstreamGroup:
//
//	{
//	   db_id: vuln id
//	   upstream_ids: list of upstream vuln ids
//	   last_modified_date: date
//	   upstream_hierarchy: JSON string of upstream hierarchy
//	}
func computeUpstreamHierarchy(ctx context.Context, cl *datastore.Client, targetUpstreamGroup *models.UpstreamGroup, allUpstreamGroups map[string]*models.UpstreamGroup) error {
	visited := make(map[string]struct{})
	upstreamMap := make(map[string][]string)
	toVisit := []string{targetUpstreamGroup.VulnID}
	// BFS navigation through the upstream hierarchy of a given upstream group
	for len(toVisit) > 0 {
		vulnID := toVisit[0]
		toVisit = toVisit[1:]
		if _, ok := visited[vulnID]; ok {
			continue
		}
		visited[vulnID] = struct{}{}
		group := allUpstreamGroups[vulnID]
		if group == nil {
			continue
		}

		if len(group.UpstreamIDs) == 0 {
			continue
		}
		for _, upstream := range group.UpstreamIDs {
			if _, ok := visited[upstream]; !ok && !slices.Contains(toVisit, upstream) {
				toVisit = append(toVisit, upstream)
			} else {
				if u, ok := upstreamMap[vulnID]; !ok {
					upstreamMap[vulnID] = []string{upstream}
				} else if !slices.Contains(u, upstream) {
					upstreamMap[vulnID] = append(u, upstream)
				}
			}
		}
		// Add the immediate upstreams of the vuln to the map
		upstreamMap[vulnID] = group.UpstreamIDs
		for _, upstream := range group.UpstreamIDs {
			if _, ok := visited[upstream]; !ok && !slices.Contains(toVisit, upstream) {
				toVisit = append(toVisit, upstream)
			}
		}
	}

	// Ensure there are no duplicate entries where transitive vulns appear
	for k, v := range upstreamMap {
		if k == targetUpstreamGroup.VulnID {
			continue
		}
		newGroup := make([]string, 0, len(upstreamMap[targetUpstreamGroup.VulnID]))
		for _, upstream := range upstreamMap[targetUpstreamGroup.VulnID] {
			if !slices.Contains(v, upstream) {
				newGroup = append(newGroup, upstream)
			}
		}
		upstreamMap[targetUpstreamGroup.VulnID] = newGroup
	}

	if len(upstreamMap) == 0 {
		return nil
	}
	// Update the datastore entry if hierarchy has changed
	// Sort the upstreams to ensure consistent ordering
	for _, v := range upstreamMap {
		slices.Sort(v)
	}
	upstreamJSON, err := json.Marshal(upstreamMap)
	if err != nil {
		return err
	}
	if bytes.Equal(upstreamJSON, targetUpstreamGroup.UpstreamHierarchy) {
		return nil
	}
	targetUpstreamGroup.UpstreamHierarchy = upstreamJSON
	_, err = cl.Put(ctx, targetUpstreamGroup.Key, targetUpstreamGroup)

	return err
}

func ComputeUpstreamGroups(ctx context.Context, cl *datastore.Client, ch chan<- Update) error {
	// Query for all vulns that have upstreams.
	var updatedGroups []*models.UpstreamGroup
	logger.Info("Retrieving vulns for upstream computation...")
	query := datastore.NewQuery("Vulnerability").FilterField("upstream_raw", ">", "")
	it := cl.Run(ctx, query)

	rawUpstreams := make(map[string][]string)
	for {
		var vuln models.Vulnerability
		_, err := it.Next(&vuln)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate vulnerabilities: %w", err)
		}
		upstream := slices.Clone(vuln.UpstreamRaw)
		slices.Sort(upstream)
		upstream = slices.Compact(upstream)
		rawUpstreams[vuln.Key.Name] = upstream
	}
	logger.Info("Vulns successfully retrieved", slog.Int("count", len(rawUpstreams)))

	logger.Info("Retrieving upstream groups...")
	query = datastore.NewQuery("UpstreamGroup")
	it = cl.Run(ctx, query)
	upstreamGroups := make(map[string]*models.UpstreamGroup)
	for {
		var group models.UpstreamGroup
		_, err := it.Next(&group)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate upstream groups: %w", err)
		}
		upstreamGroups[group.VulnID] = &group
	}
	logger.Info("Upstream groups successfully retrieved", slog.Int("count", len(upstreamGroups)))

	for vulnID := range rawUpstreams {
		// Get the specific upstream existingUpstreamGroup ID
		existingUpstreamGroup, exists := upstreamGroups[vulnID]
		// Recompute the transitive upstreams and compare with the existing group
		newUpstreamIDs := computeUpstream(vulnID, rawUpstreams)
		if exists {
			// Update the existing UpstreamGroup
			var err error
			existingUpstreamGroup, err = updateUpstreamGroup(ctx, cl, existingUpstreamGroup, newUpstreamIDs, ch)
			if err != nil {
				return fmt.Errorf("failed to update upstream group: %w", err)
			}
			if existingUpstreamGroup == nil {
				continue
			}
			updatedGroups = append(updatedGroups, existingUpstreamGroup)
			upstreamGroups[vulnID] = existingUpstreamGroup
			logger.Info("Upstream group updated", slog.String("id", vulnID))
		} else {
			// Create a new UpstreamGroup
			newGroup, err := createUpstreamGroup(ctx, cl, vulnID, newUpstreamIDs, ch)
			if err != nil {
				return fmt.Errorf("failed to create upstream group: %w", err)
			}
			updatedGroups = append(updatedGroups, newGroup)
			upstreamGroups[vulnID] = newGroup
		}
	}

	for _, group := range updatedGroups {
		// Recompute the upstream hierarchies
		if err := computeUpstreamHierarchy(ctx, cl, group, upstreamGroups); err != nil {
			return fmt.Errorf("failed to compute upstream hierarchy: %w", err)
		}
		logger.Info("Upstream hierarchy updated", slog.String("id", group.VulnID))
	}

	return nil
}
