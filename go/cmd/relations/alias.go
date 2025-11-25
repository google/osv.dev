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

const (
	aliasGroupVulnLimit = 32
	vulnAliasesLimit    = 5
)

func updateGroup(ctx context.Context, cl *datastore.Client, vulnIDs []string,
	key *datastore.Key, group models.AliasGroup, changedVulns map[string]*models.AliasGroup) error {
	if len(vulnIDs) <= 1 {
		logger.Info("Deleting alias group due to too few vulns", slog.Any("ids", vulnIDs))
		for _, vID := range vulnIDs {
			changedVulns[vID] = nil
		}
		return cl.Delete(ctx, key)
	}
	if len(vulnIDs) > aliasGroupVulnLimit {
		logger.Warn("Deleting alias group due to too many vulns", slog.Any("ids", vulnIDs))
		for _, vID := range vulnIDs {
			changedVulns[vID] = nil
		}
		return cl.Delete(ctx, key)
	}

	if slices.Equal(vulnIDs, group.VulnIDs) {
		return nil
	}

	group.VulnIDs = vulnIDs
	group.Modified = time.Now().UTC()
	if _, err := cl.Put(ctx, key, &group); err != nil {
		return err
	}
	for _, vID := range vulnIDs {
		changedVulns[vID] = &group
	}
	return nil
}

func createAliasGroup(ctx context.Context, cl *datastore.Client, vulnIDs []string, changedVulns map[string]*models.AliasGroup) error {
	if len(vulnIDs) <= 1 {
		logger.Info("Skipping alias group creation due to too few vulns", slog.Any("vulnIDs", vulnIDs))
		return nil
	}
	if len(vulnIDs) > aliasGroupVulnLimit {
		logger.Warn("Skipping alias group creation due to too many vulns", slog.Any("vulnIDs", vulnIDs))
		return nil
	}

	newGroup := &models.AliasGroup{
		VulnIDs:  vulnIDs,
		Modified: time.Now().UTC(),
	}

	if _, err := cl.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), newGroup); err != nil {
		return err
	}

	for _, vulnID := range vulnIDs {
		changedVulns[vulnID] = newGroup
	}

	return nil
}

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

func updateVulnWithGroup(ch chan<- Update, vulnID string, aliasGroup *models.AliasGroup) {
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

func ComputeAliasGroups(ctx context.Context, cl *datastore.Client, ch chan<- Update) error {
	query := datastore.NewQuery("AliasAllowListEntry")
	var allowListEntries []models.AliasAllowListEntry
	if _, err := cl.GetAll(ctx, query, &allowListEntries); err != nil {
		return fmt.Errorf("failed querying AliasAllowListEntries: %w", err)
	}
	allowList := make(map[string]struct{})
	for _, ale := range allowListEntries {
		allowList[ale.VulnID] = struct{}{}
	}
	query = datastore.NewQuery("AliasDenyListEntry")
	var denyListEntries []models.AliasDenyListEntry
	if _, err := cl.GetAll(ctx, query, &denyListEntries); err != nil {
		return fmt.Errorf("failed querying AliasDenyListEntries: %w", err)
	}
	denyList := make(map[string]struct{})
	for _, dle := range denyListEntries {
		denyList[dle.VulnID] = struct{}{}
	}

	// Mapping of ID to a set of all aliases for that vuln,
	// including its raw aliases and vulns that it is referenced in as an alias.
	vulnAliases := make(map[string]map[string]struct{})
	// For each vuln, add its aliases to the maps and ignore invalid vulns.
	query = datastore.NewQuery("Vulnerability").FilterField("alias_raw", ">", "")
	it := cl.Run(ctx, query)
	for {
		var vuln models.Vulnerability
		_, err := it.Next(&vuln)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			logger.Error("failed iterating vulnerabilities", slog.Any("err", err))
			return err
		}
		vulnID := vuln.Key.Name
		if vuln.IsWithdrawn {
			continue
		}
		if _, ok := denyList[vulnID]; ok {
			continue
		}
		if _, ok := allowList[vulnID]; len(vuln.AliasRaw) > vulnAliasesLimit && !ok {
			logger.Warn("Skipping computation of vuln with too many aliases",
				slog.String("id", vulnID), slog.Any("aliases", vuln.AliasRaw))
			continue
		}
		for _, alias := range vuln.AliasRaw {
			addToSet(vulnAliases, vulnID, alias)
			addToSet(vulnAliases, alias, vulnID)
		}

	}

	visited := make(map[string]struct{})

	// Keep track of vulnerabilities that have been modified, to update GCS later.
	// nil means the AliasGroup has been removed
	changedVulns := make(map[string]*models.AliasGroup)

	// For each alias group, re-compute the vuln IDs in the group and update the group
	// with the computed vuln IDs.
	query = datastore.NewQuery("AliasGroup")
	it = cl.Run(ctx, query)
	for {
		var aliasGroup models.AliasGroup
		key, err := it.Next(&aliasGroup)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to query AliasGroups: %w", err)
		}
		vulnID := aliasGroup.VulnIDs[0] // AliasGroups always contain more than one vuln
		// If the vuln has already been counted in a different alias group,
		// we delete the original one to merge the two alias groups.
		if _, ok := visited[vulnID]; ok {
			for _, vID := range aliasGroup.VulnIDs {
				if _, ok := changedVulns[vID]; !ok {
					changedVulns[vID] = nil
				}
			}
			if err := cl.Delete(ctx, key); err != nil {
				return err
			}
			continue
		}
		vulnIDs := computeAliases(vulnID, visited, vulnAliases)
		if err := updateGroup(ctx, cl, vulnIDs, key, aliasGroup, changedVulns); err != nil {
			return fmt.Errorf("failed to update AliasGroup: %w", err)
		}
	}

	// For each vuln ID that has not been visited, create new alias groups.
	for vulnID := range vulnAliases {
		if _, ok := visited[vulnID]; !ok {
			vulnIDs := computeAliases(vulnID, visited, vulnAliases)
			if err := createAliasGroup(ctx, cl, vulnIDs, changedVulns); err != nil {
				return fmt.Errorf("failed to create AliasGroup: %w", err)
			}
		}
	}

	// For each updated vulnerability, update them in Datastore & GCS
	for vulnID, aliasGroup := range changedVulns {
		updateVulnWithGroup(ch, vulnID, aliasGroup)
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
