// Copyright 2024 Google LLC
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
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	internalmodels "github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

const (
	aliasGroupVulnLimit = 32
	vulnAliasesLimit    = 5
)

// updateAliasGroup updates an existing alias group in the store.
func updateAliasGroup(ctx context.Context, store internalmodels.RelationsComputationStore, vulnIDs []string, key string, group internalmodels.AliasGroup, changedVulns map[string]*internalmodels.AliasGroup) error {
	if len(vulnIDs) <= 1 {
		logger.Info("Deleting alias group due to too few vulns", slog.Any("vulnIDs", vulnIDs))
		for _, vID := range group.VulnIDs {
			changedVulns[vID] = nil
		}

		return store.DeleteAliasGroup(ctx, key)
	}

	if slices.Equal(vulnIDs, group.VulnIDs) {
		return nil
	}

	group.VulnIDs = vulnIDs
	group.Modified = time.Now().UTC()
	if err := store.SaveAliasGroup(ctx, &group); err != nil {
		return err
	}
	for _, vID := range vulnIDs {
		changedVulns[vID] = &group
	}

	return nil
}

// createAliasGroup creates a new alias group in the store.
func createAliasGroup(ctx context.Context, store internalmodels.RelationsComputationStore, vulnIDs []string, changedVulns map[string]*internalmodels.AliasGroup) error {
	if len(vulnIDs) <= 1 {
		logger.Info("Skipping alias group creation due to too few vulns", slog.Any("vulnIDs", vulnIDs))
		return nil
	}
	if len(vulnIDs) > aliasGroupVulnLimit {
		logger.Warn("Skipping alias group creation due to too many vulns", slog.Any("vulnIDs", vulnIDs))
		return nil
	}

	newGroup := &internalmodels.AliasGroup{
		VulnIDs:  vulnIDs,
		Modified: time.Now().UTC(),
	}

	if err := store.SaveAliasGroup(ctx, newGroup); err != nil {
		return err
	}

	for _, vulnID := range vulnIDs {
		changedVulns[vulnID] = newGroup
	}

	return nil
}

// computeAliases computes all aliases for the given vuln ID.
// The returned slice contains the vuln ID itself, all the IDs from the vuln's raw aliases, all the IDs of vulns that have
// the current vuln as an alias, and repeat for every vuln encountered.
func computeAliases(vulnID string, visited map[string]struct{}, vulnAliases map[string]map[string]struct{}) []string {
	toVisit := []string{vulnID}
	var vulnIDs []string
	for len(toVisit) > 0 {
		vulnID, toVisit = toVisit[0], toVisit[1:]
		if _, ok := visited[vulnID]; ok {
			continue
		}
		visited[vulnID] = struct{}{}
		vulnIDs = append(vulnIDs, vulnID)

		for aliasID := range vulnAliases[vulnID] {
			if !slices.Contains(toVisit, aliasID) {
				toVisit = append(toVisit, aliasID)
			}
		}
	}
	// Returns a sorted list of vuln IDs, which ensures deterministic behaviour
	// and avoids unnecessary updates to the groups.
	slices.Sort(vulnIDs)

	return vulnIDs
}

// updateVulnWithAliasGroup sends an update for the vuln in Datastore and GCS with the new alias group.
// if aliasGroup is nil, assumes a preexisting AliasGroup was just deleted.
func updateVulnWithAliasGroup(ch chan<- Update, vulnID string, aliasGroup *internalmodels.AliasGroup) {
	update := Update{ID: vulnID, Field: updateFieldAlias}
	if aliasGroup == nil {
		update.Timestamp = time.Now().UTC()
		update.Value = []string(nil)
	} else {
		update.Timestamp = aliasGroup.Modified
		vulns := slices.Clone(aliasGroup.VulnIDs)
		idx := slices.Index(vulns, vulnID)
		vulns = slices.Delete(vulns, idx, idx+1)
		update.Value = vulns
	}
	ch <- update
}

// ComputeAliasGroups updates all alias groups in the datastore by re-computing existing AliasGroups
// and creating new AliasGroups for un-computed vulns across key shards.
func ComputeAliasGroups(ctx context.Context, store internalmodels.RelationsComputationStore, ch chan<- Update) error {
	allowList, denyList, err := store.GetAliasAllowAndDenyLists(ctx)
	if err != nil {
		return err
	}

	logger.Info("Retrieving vulns for alias computation...")
	vulnAliases := make(map[string]map[string]struct{})
	err = store.ListRawAliases(ctx, func(ref internalmodels.RawAliasRef) {
		vulnID := ref.ID
		if ref.IsWithdrawn {
			return
		}
		if _, ok := denyList[vulnID]; ok {
			return
		}
		if _, ok := allowList[vulnID]; len(ref.Aliases) > vulnAliasesLimit && !ok {
			logger.Warn("Skipping computation of vuln with too many aliases",
				slog.String("id", vulnID), slog.Any("aliases", ref.Aliases))

			return
		}

		for _, alias := range ref.Aliases {
			if _, ok := denyList[alias]; ok {
				continue
			}
			addToSet(vulnAliases, vulnID, alias)
			addToSet(vulnAliases, alias, vulnID)
		}
	})
	if err != nil {
		return fmt.Errorf("failed retrieving raw aliases: %w", err)
	}
	logger.Info("Vulns successfully retrieved", slog.Int("count", len(vulnAliases)))

	visited := make(map[string]struct{})

	// Keep track of vulnerabilities that have been modified, to update GCS later.
	// nil means the AliasGroup has been removed
	changedVulns := make(map[string]*internalmodels.AliasGroup)

	// For each alias group, re-compute the vuln IDs in the group and update the group
	// with the computed vuln IDs.
	err = store.FetchAliasGroups(ctx, func(key string, aliasGroup internalmodels.AliasGroup) {
		vulnID := aliasGroup.VulnIDs[0] // AliasGroups always contain more than one vuln
		// If the vuln has already been counted in a different alias group,
		// we delete the original one to merge the two alias groups.
		if _, ok := visited[vulnID]; ok {
			for _, vID := range aliasGroup.VulnIDs {
				if _, ok := changedVulns[vID]; !ok {
					changedVulns[vID] = nil
				}
			}
			if err := store.DeleteAliasGroup(ctx, key); err != nil {
				logger.ErrorContext(ctx, "failed to delete AliasGroup", slog.String("key", key), slog.Any("err", err))
			}

			return
		}
		vulnIDs := computeAliases(vulnID, visited, vulnAliases)
		if err := updateAliasGroup(ctx, store, vulnIDs, key, aliasGroup, changedVulns); err != nil {
			logger.ErrorContext(ctx, "failed to update AliasGroup", slog.String("key", key), slog.Any("err", err))
		}
	})
	if err != nil {
		return fmt.Errorf("failed fetching alias groups: %w", err)
	}

	// For each vuln ID that has not been visited, create new alias groups.
	for vulnID := range vulnAliases {
		if _, ok := visited[vulnID]; !ok {
			vulnIDs := computeAliases(vulnID, visited, vulnAliases)
			if err := createAliasGroup(ctx, store, vulnIDs, changedVulns); err != nil {
				return fmt.Errorf("failed to create AliasGroup: %w", err)
			}
		}
	}

	// For each updated vulnerability, update them in Datastore & GCS
	for vulnID, aliasGroup := range changedVulns {
		updateVulnWithAliasGroup(ch, vulnID, aliasGroup)
	}

	return nil
}

func addToSet(sets map[string]map[string]struct{}, key, value string) {
	m, ok := sets[key]
	if !ok {
		m = make(map[string]struct{})
		sets[key] = m
	}
	m[value] = struct{}{}
}
