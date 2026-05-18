package datastore

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
