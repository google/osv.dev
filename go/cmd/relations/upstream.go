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

func computeUpstream(targetBugUpstream []string, bugs map[string][]string) []string {
	visited := make(map[string]struct{})
	toVisit := slices.Clone(targetBugUpstream)

	var result []string
	for len(toVisit) > 0 {
		bugID := toVisit[0]
		toVisit = toVisit[1:]

		if _, ok := visited[bugID]; ok {
			continue
		}
		visited[bugID] = struct{}{}
		result = append(result, bugID)

		if upstreams, ok := bugs[bugID]; ok {
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

func updateUpstreamGroup(ctx context.Context, cl *datastore.Client, group *models.UpstreamGroup, upstreamIDs []string, ch chan<- Update) (*models.UpstreamGroup, error) {
	if len(upstreamIDs) == 0 {
		logger.Info("Deleting upstream group due to too few bugs", slog.String("id", group.VulnID))
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

func updateVulnWithUpstream(ch chan<- Update, vulnID string, group *models.UpstreamGroup) {
	update := Update{ID: vulnID, Field: updateFieldUpstream}
	if group == nil {
		update.Timestamp = time.Now().UTC()
		update.Value = []string(nil)
	} else {
		update.Timestamp = group.Modified
		update.Value = group.UpstreamIDs
	}
	ch <- update
}

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

	// Update the datastore entry if hierarchy has changed
	if len(upstreamMap) == 0 {
		return nil
	}
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

	vulns := make(map[string][]string)
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
		vulns[vuln.Key.Name] = upstream
	}
	logger.Info("Vulns successfully retrieved", slog.Int("count", len(vulns)))

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

	for vulnID, upstreams := range vulns {
		// Get the specific upstream group ID
		group, exists := upstreamGroups[vulnID]
		// Recompute the transitive upstreams and compare with the existing group
		upstreamIDs := computeUpstream(upstreams, vulns)
		if exists {
			if slices.Equal(upstreamIDs, group.UpstreamIDs) {
				continue
			}
			// Update the existing UpstreamGroup
			var err error
			group, err = updateUpstreamGroup(ctx, cl, group, upstreamIDs, ch)
			if err != nil {
				return fmt.Errorf("failed to update upstream group: %w", err)
			}
			if group == nil {
				continue
			}
			updatedGroups = append(updatedGroups, group)
			upstreamGroups[vulnID] = group
			logger.Info("Upstream group updated", slog.String("id", vulnID))
		} else {
			// Create a new UpstreamGroup
			newGroup, err := createUpstreamGroup(ctx, cl, vulnID, upstreamIDs, ch)
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
