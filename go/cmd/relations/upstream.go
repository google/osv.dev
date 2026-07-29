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
	"fmt"
	"log/slog"
	"slices"
	"time"

	internalmodels "github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
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

// createUpstreamGroup creates a new upstream group in the store and sends it to the updater.
func createUpstreamGroup(ctx context.Context, store internalmodels.RelationsComputationStore, vulnID string, upstreamIDs []string, ch chan<- Update) (*internalmodels.UpstreamGroup, error) {
	group := &internalmodels.UpstreamGroup{
		VulnID:      vulnID,
		UpstreamIDs: upstreamIDs,
		Modified:    time.Now().UTC(),
	}
	if err := store.SaveUpstreamGroup(ctx, group); err != nil {
		return nil, err
	}
	updateVulnWithUpstream(ch, vulnID, group)

	return group, nil
}

// updateUpstreamGroup updates the upstream group in the store, and sends it to the updater.
func updateUpstreamGroup(ctx context.Context, store internalmodels.RelationsComputationStore, group *internalmodels.UpstreamGroup, upstreamIDs []string, ch chan<- Update) (*internalmodels.UpstreamGroup, error) {
	if len(upstreamIDs) == 0 {
		logger.Info("Deleting upstream group due to no upstream vulns", slog.String("id", group.VulnID))
		if err := store.DeleteUpstreamGroup(ctx, group.VulnID); err != nil {
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
	if err := store.SaveUpstreamGroup(ctx, group); err != nil {
		return nil, err
	}
	updateVulnWithUpstream(ch, group.VulnID, group)

	return group, nil
}

// updateVulnWithUpstream sends an update for the vuln in Datastore & GCS with the new upstream group.
// If group is nil, assumes a preexisting UpstreamGroup was just deleted.
func updateVulnWithUpstream(ch chan<- Update, vulnID string, group *internalmodels.UpstreamGroup) {
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
func computeUpstreamHierarchy(ctx context.Context, store internalmodels.RelationsComputationStore, targetUpstreamGroup *internalmodels.UpstreamGroup, allUpstreamGroups map[string]*internalmodels.UpstreamGroup) error {
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

	return store.SaveUpstreamGroup(ctx, targetUpstreamGroup)
}

// ComputeUpstreamGroups updates all upstream groups in the datastore by re-computing existing UpstreamGroups
// and creating new UpstreamGroups across key shards.
func ComputeUpstreamGroups(ctx context.Context, store internalmodels.RelationsComputationStore, ch chan<- Update) error {
	var updatedGroups []*internalmodels.UpstreamGroup
	logger.Info("Retrieving vulns for upstream computation...")
	rawUpstreams := make(map[string][]string)
	err := store.ListRawUpstreams(ctx, func(ref internalmodels.RawUpstreamRef) {
		upstream := slices.Clone(ref.Upstreams)
		slices.Sort(upstream)
		rawUpstreams[ref.ID] = slices.Compact(upstream)
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve raw upstreams: %w", err)
	}
	logger.Info("Vulns successfully retrieved", slog.Int("count", len(rawUpstreams)))

	logger.Info("Retrieving upstream groups...")
	upstreamGroups := make(map[string]*internalmodels.UpstreamGroup)
	err = store.FetchUpstreamGroups(ctx, func(id string, group internalmodels.UpstreamGroup) {
		g := group
		upstreamGroups[id] = &g
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve upstream groups: %w", err)
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
			existingUpstreamGroup, err = updateUpstreamGroup(ctx, store, existingUpstreamGroup, newUpstreamIDs, ch)
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
			newGroup, err := createUpstreamGroup(ctx, store, vulnID, newUpstreamIDs, ch)
			if err != nil {
				return fmt.Errorf("failed to create upstream group: %w", err)
			}
			if newGroup == nil {
				continue
			}
			updatedGroups = append(updatedGroups, newGroup)
			upstreamGroups[vulnID] = newGroup
			logger.Info("Upstream group created", slog.String("id", vulnID))
		}
	}

	for _, group := range updatedGroups {
		// Recompute the upstream hierarchies
		if err := computeUpstreamHierarchy(ctx, store, group, upstreamGroups); err != nil {
			return fmt.Errorf("failed to compute upstream hierarchy: %w", err)
		}
		logger.Info("Upstream hierarchy updated", slog.String("id", group.VulnID))
	}

	return nil
}
