package datastore

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/sharding"
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

func (s *RelationsStore) GetUpstream(ctx context.Context, id string) (*models.GetUpstreamResult, error) {
	var upstreamGroup UpstreamGroup
	err := s.client.Get(ctx, datastore.NameKey("UpstreamGroup", id, nil), &upstreamGroup)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream group: %w", err)
	}
	upstream := make([]string, len(upstreamGroup.UpstreamIDs))
	copy(upstream, upstreamGroup.UpstreamIDs)
	slices.Sort(upstream)

	return &models.GetUpstreamResult{
		Upstream: upstream,
		Modified: upstreamGroup.Modified,
	}, nil
}

type RelationsComputationStore struct {
	client    *datastore.Client
	keyShards []sharding.KeyShard
}

var _ models.RelationsComputationStore = (*RelationsComputationStore)(nil)

func NewRelationsComputationStore(client *datastore.Client, breakdownPrefixesStr string) *RelationsComputationStore {
	return &RelationsComputationStore{
		client:    client,
		keyShards: sharding.ParseBreakdownPrefixes(breakdownPrefixesStr),
	}
}

func (s *RelationsComputationStore) ListRawAliases(ctx context.Context, handle func(ref models.RawAliasRef)) error {
	return sharding.RunShardedQuery(
		ctx, s.client, s.keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("Vulnerability").FilterField("alias_raw", ">", "")

			return sharding.ApplyNameKeyFilter(query, "Vulnerability", shard)
		},
		func(key *datastore.Key, vuln *Vulnerability) {
			ref := models.RawAliasRef{
				ID:          key.Name,
				Aliases:     vuln.AliasRaw,
				IsWithdrawn: vuln.IsWithdrawn,
			}
			handle(ref)
		},
	)
}

func (s *RelationsComputationStore) ListRawUpstreams(ctx context.Context, handle func(ref models.RawUpstreamRef)) error {
	return sharding.RunShardedQuery(
		ctx, s.client, s.keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("Vulnerability").FilterField("upstream_raw", ">", "")

			return sharding.ApplyNameKeyFilter(query, "Vulnerability", shard)
		},
		func(key *datastore.Key, vuln *Vulnerability) {
			ref := models.RawUpstreamRef{
				ID:        key.Name,
				Upstreams: vuln.UpstreamRaw,
			}
			handle(ref)
		},
	)
}

func (s *RelationsComputationStore) ListRawRelated(ctx context.Context, handle func(ref models.RawRelatedRef)) error {
	return sharding.RunShardedQuery(
		ctx, s.client, s.keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("Vulnerability").FilterField("related_raw", ">", "")

			return sharding.ApplyNameKeyFilter(query, "Vulnerability", shard)
		},
		func(key *datastore.Key, vuln *Vulnerability) {
			ref := models.RawRelatedRef{
				ID:          key.Name,
				RelatedIDs:  vuln.RelatedRaw,
				IsWithdrawn: vuln.IsWithdrawn,
			}
			handle(ref)
		},
	)
}

func (s *RelationsComputationStore) GetAliasAllowAndDenyLists(ctx context.Context) (map[string]struct{}, map[string]struct{}, error) {
	queryAllow := datastore.NewQuery("AliasAllowListEntry")
	var allowListEntries []AliasAllowListEntry
	if _, err := s.client.GetAll(ctx, queryAllow, &allowListEntries); err != nil {
		return nil, nil, fmt.Errorf("failed querying AliasAllowListEntries: %w", err)
	}
	allowList := make(map[string]struct{}, len(allowListEntries))
	for _, ale := range allowListEntries {
		allowList[ale.VulnID] = struct{}{}
	}

	queryDeny := datastore.NewQuery("AliasDenyListEntry")
	var denyListEntries []AliasDenyListEntry
	if _, err := s.client.GetAll(ctx, queryDeny, &denyListEntries); err != nil {
		return nil, nil, fmt.Errorf("failed querying AliasDenyListEntries: %w", err)
	}
	denyList := make(map[string]struct{}, len(denyListEntries))
	for _, dle := range denyListEntries {
		denyList[dle.VulnID] = struct{}{}
	}

	return allowList, denyList, nil
}

func (s *RelationsComputationStore) FetchAliasGroups(ctx context.Context, handle func(id string, group models.AliasGroup)) error {
	query := datastore.NewQuery("AliasGroup")
	var aliasGroups []AliasGroup
	keys, err := s.client.GetAll(ctx, query, &aliasGroups)
	if err != nil {
		return fmt.Errorf("failed retrieving alias groups: %w", err)
	}
	for i, group := range aliasGroups {
		mGroup := models.AliasGroup{
			VulnIDs:  group.VulnIDs,
			Modified: group.Modified,
		}
		handle(keys[i].Name, mGroup)
	}

	return nil
}

func (s *RelationsComputationStore) SaveAliasGroup(ctx context.Context, group *models.AliasGroup) error {
	dsGroup := AliasGroup{
		VulnIDs:  group.VulnIDs,
		Modified: group.Modified,
	}
	_, err := s.client.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), &dsGroup)

	return err
}

func (s *RelationsComputationStore) DeleteAliasGroup(ctx context.Context, id string) error {
	return s.client.Delete(ctx, datastore.NameKey("AliasGroup", id, nil))
}

func (s *RelationsComputationStore) FetchUpstreamGroups(ctx context.Context, handle func(id string, group models.UpstreamGroup)) error {
	return sharding.RunShardedQuery(
		ctx, s.client, s.keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("UpstreamGroup")
			if shard.Start != "" {
				query = query.FilterField("db_id", ">=", shard.Start)
			}
			if shard.End != "" {
				query = query.FilterField("db_id", "<", shard.End)
			}

			return query
		},
		func(_ *datastore.Key, group *UpstreamGroup) {
			mGroup := models.UpstreamGroup{
				VulnID:            group.VulnID,
				UpstreamIDs:       group.UpstreamIDs,
				Modified:          group.Modified,
				UpstreamHierarchy: group.UpstreamHierarchy,
			}
			handle(group.VulnID, mGroup)
		},
	)
}

func (s *RelationsComputationStore) SaveUpstreamGroup(ctx context.Context, group *models.UpstreamGroup) error {
	dsGroup := UpstreamGroup{
		VulnID:            group.VulnID,
		UpstreamIDs:       group.UpstreamIDs,
		Modified:          group.Modified,
		UpstreamHierarchy: group.UpstreamHierarchy,
	}
	key := datastore.IncompleteKey("UpstreamGroup", nil)
	_, err := s.client.Put(ctx, key, &dsGroup)

	return err
}

func (s *RelationsComputationStore) DeleteUpstreamGroup(ctx context.Context, id string) error {
	return s.client.Delete(ctx, datastore.NameKey("UpstreamGroup", id, nil))
}

func (s *RelationsComputationStore) FetchRelatedGroups(ctx context.Context, handle func(id string, group models.RelatedGroup)) error {
	return sharding.RunShardedQuery(
		ctx, s.client, s.keyShards,
		func(shard sharding.KeyShard) *datastore.Query {
			query := datastore.NewQuery("RelatedGroup")

			return sharding.ApplyNameKeyFilter(query, "RelatedGroup", shard)
		},
		func(key *datastore.Key, group *RelatedGroup) {
			mGroup := models.RelatedGroup{
				VulnID:     key.Name,
				RelatedIDs: group.RelatedIDs,
				Modified:   group.Modified,
			}
			handle(key.Name, mGroup)
		},
	)
}

func (s *RelationsComputationStore) SaveRelatedGroup(ctx context.Context, group *models.RelatedGroup) error {
	key := datastore.NameKey("RelatedGroup", group.VulnID, nil)
	dsGroup := RelatedGroup{
		RelatedIDs: group.RelatedIDs,
		Modified:   group.Modified,
	}
	_, err := s.client.Put(ctx, key, &dsGroup)

	return err
}

func (s *RelationsComputationStore) DeleteRelatedGroup(ctx context.Context, id string) error {
	return s.client.Delete(ctx, datastore.NameKey("RelatedGroup", id, nil))
}
