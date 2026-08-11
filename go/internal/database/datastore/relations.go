package datastore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

type RelationsStore struct {
	client *datastore.Client
}

var _ models.RelationsStore = (*RelationsStore)(nil)

func NewRelationsStore(client *datastore.Client) *RelationsStore {
	return &RelationsStore{client: client}
}

func (s *RelationsStore) GetAliases(ctx context.Context, id string) (*models.GetAliasResult, error) {
	var aliasGroups []AliasGroup
	q := datastore.NewQuery("AliasGroup").FilterField("bug_ids", "=", id)
	_, err := s.client.GetAll(ctx, q, &aliasGroups)
	if err != nil {
		return nil, fmt.Errorf("failed to get alias group: %w", err)
	}
	if len(aliasGroups) == 0 {
		return nil, models.ErrNotFound
	}
	if len(aliasGroups) > 1 {
		return nil, errors.New("id belongs to multiple aliases")
	}
	aliasGroup := aliasGroups[0]
	aliases := make([]string, 0, len(aliasGroup.VulnIDs)-1)
	for _, vulnID := range aliasGroup.VulnIDs {
		if vulnID != id {
			aliases = append(aliases, vulnID)
		}
	}
	slices.Sort(aliases)

	return &models.GetAliasResult{
		Aliases:  aliases,
		Modified: aliasGroup.Modified,
	}, nil
}

func (s *RelationsStore) GetRelated(ctx context.Context, id string) (*models.GetRelatedResult, error) {
	var relatedGroup RelatedGroup
	err := s.client.Get(ctx, datastore.NameKey("RelatedGroup", id, nil), &relatedGroup)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get related group: %w", err)
	}
	related := make([]string, len(relatedGroup.RelatedIDs))
	copy(related, relatedGroup.RelatedIDs)
	slices.Sort(related)

	return &models.GetRelatedResult{
		Related:  related,
		Modified: relatedGroup.Modified,
	}, nil
}

func (s *RelationsStore) getUpstreamGroup(ctx context.Context, id string) (*UpstreamGroup, error) {
	var groups []UpstreamGroup
	q := datastore.NewQuery("UpstreamGroup").FilterField("db_id", "=", id).Limit(1)
	_, err := s.client.GetAll(ctx, q, &groups)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream group: %w", err)
	}
	if len(groups) == 0 {
		return nil, models.ErrNotFound
	}

	return &groups[0], nil
}

func (s *RelationsStore) GetUpstream(ctx context.Context, id string) (*models.GetUpstreamResult, error) {
	upstreamGroup, err := s.getUpstreamGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	upstream := make([]string, len(upstreamGroup.UpstreamIDs))
	copy(upstream, upstreamGroup.UpstreamIDs)
	slices.Sort(upstream)

	return &models.GetUpstreamResult{
		Upstream: upstream,
		Modified: upstreamGroup.Modified,
	}, nil
}

func (s *RelationsStore) GetUpstreamHierarchy(ctx context.Context, id string) (*models.Hierarchy, error) {
	upstreamGroup, err := s.getUpstreamGroup(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(upstreamGroup.UpstreamHierarchy) == 0 {
		return nil, models.ErrNotFound
	}

	var rawHierarchy map[string][]string
	if err := json.Unmarshal(upstreamGroup.UpstreamHierarchy, &rawHierarchy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal upstream hierarchy JSON: %w", err)
	}

	return ComputeUpstreamHierarchy(id, rawHierarchy)
}

func (s *RelationsStore) GetDownstreamHierarchy(ctx context.Context, id string) (*models.Hierarchy, error) {
	var groups []UpstreamGroup
	q := datastore.NewQuery("UpstreamGroup").FilterField("upstream_ids", "=", id)
	_, err := s.client.GetAll(ctx, q, &groups)
	if err != nil {
		return nil, fmt.Errorf("failed to query downstream groups: %w", err)
	}
	if len(groups) == 0 {
		return nil, models.ErrNotFound
	}

	downstreams := make(map[string][]string, len(groups))
	for _, g := range groups {
		vulnID := g.VulnID
		if vulnID == "" && g.Key != nil {
			vulnID = g.Key.Name
		}
		if vulnID != "" {
			downstreams[vulnID] = g.UpstreamIDs
		}
	}

	return ComputeDownstreamHierarchy(id, downstreams)
}

func reverseTree(graph map[string][]string) map[string][]string {
	reversed := make(map[string][]string)
	for node, children := range graph {
		for _, child := range children {
			reversed[child] = append(reversed[child], node)
		}
	}
	for k := range reversed {
		slices.Sort(reversed[k])
	}

	return reversed
}

func hasCycle(graph map[string][]string) bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(node string) bool
	dfs = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range graph[node] {
			if recStack[neighbor] {
				return true
			}
			if !visited[neighbor] {
				if dfs(neighbor) {
					return true
				}
			}
		}

		recStack[node] = false

		return false
	}

	for node := range graph {
		if !visited[node] {
			if dfs(node) {
				return true
			}
		}
	}

	return false
}

// ComputeUpstreamHierarchy computes a directed upstream hierarchy from a raw parent-to-children graph.
func ComputeUpstreamHierarchy(targetID string, rawHierarchy map[string][]string) (*models.Hierarchy, error) {
	if len(rawHierarchy) == 0 {
		return nil, models.ErrNotFound
	}

	reversed := reverseTree(rawHierarchy)
	if hasCycle(reversed) {
		return nil, fmt.Errorf("cycle detected in upstream hierarchy for %s", targetID)
	}

	allChildren := make(map[string]bool)
	for _, children := range rawHierarchy {
		for _, c := range children {
			allChildren[c] = true
		}
	}

	var rootNodes []string
	for child := range allChildren {
		if _, exists := rawHierarchy[child]; !exists {
			rootNodes = append(rootNodes, child)
		}
	}
	slices.Sort(rootNodes)

	return &models.Hierarchy{
		Roots: rootNodes,
		Graph: reversed,
	}, nil
}

func getDownstreamsOfVuln(vulnID string, vulns map[string][]string) []string {
	var res []string
	for vuln, upstreamIDs := range vulns {
		if slices.Contains(upstreamIDs, vulnID) {
			res = append(res, vuln)
		}
	}
	slices.Sort(res)

	return res
}

// ComputeDownstreamHierarchy computes a directed downstream hierarchy given downstream bug IDs and their upstream lists.
func ComputeDownstreamHierarchy(targetID string, downstreams map[string][]string) (*models.Hierarchy, error) {
	if len(downstreams) == 0 {
		return nil, models.ErrNotFound
	}

	type item struct {
		id          string
		upstreamIDs []string
	}
	items := make([]item, 0, len(downstreams))
	for k, v := range downstreams {
		items = append(items, item{id: k, upstreamIDs: v})
	}
	slices.SortFunc(items, func(a, b item) int {
		if len(a.upstreamIDs) != len(b.upstreamIDs) {
			return len(a.upstreamIDs) - len(b.upstreamIDs)
		}

		return strings.Compare(a.id, b.id)
	})

	downstreamMap := make(map[string][]string)
	leafVulns := make(map[string]bool)

	for _, it := range items {
		immediates := getDownstreamsOfVuln(it.id, downstreams)
		if len(immediates) == 0 {
			leafVulns[it.id] = true
		} else {
			downstreamMap[it.id] = immediates
		}
	}

	rootLeaves := make(map[string]bool)
	for k := range leafVulns {
		rootLeaves[k] = true
	}

	sortedMapKeys := make([]string, 0, len(downstreamMap))
	for k := range downstreamMap {
		sortedMapKeys = append(sortedMapKeys, k)
	}
	slices.Sort(sortedMapKeys)

	for _, vulnID := range sortedMapKeys {
		downstreamBugs := downstreamMap[vulnID]
		for leaf := range leafVulns {
			if slices.Contains(downstreamBugs, leaf) {
				delete(rootLeaves, leaf)
			}
		}
		rootLeaves[vulnID] = true
	}

	roots := make([]string, 0, len(rootLeaves))
	for r := range rootLeaves {
		roots = append(roots, r)
	}
	slices.Sort(roots)

	downstreamMap[targetID] = roots

	if hasCycle(downstreamMap) {
		return nil, fmt.Errorf("cycle detected in downstream hierarchy for %s", targetID)
	}

	return &models.Hierarchy{
		Roots: roots,
		Graph: downstreamMap,
	}, nil
}
