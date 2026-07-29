// Package models contains the domain types for the OSV database.
package models

import (
	"context"
	"time"
)

type GetAliasResult struct {
	Aliases  []string
	Modified time.Time
}

type GetRelatedResult struct {
	Related  []string
	Modified time.Time
}

type GetUpstreamResult struct {
	Upstream []string
	Modified time.Time
}

type RelationsStore interface {
	// GetAliases retrieves the computed aliases for a vulnerability.
	// Returns ErrNotFound if no aliased vulnerabilities are known.
	GetAliases(ctx context.Context, id string) (*GetAliasResult, error)
	// GetRelated retrieves the computed related vulnerabilities for a vulnerability.
	// Returns ErrNotFound if no related vulnerabilities are known.
	GetRelated(ctx context.Context, id string) (*GetRelatedResult, error)
	// GetUpstream retrieves the computed upstream vulnerabilities for a vulnerability.
	// Returns ErrNotFound if no upstream vulnerabilities are known.
	GetUpstream(ctx context.Context, id string) (*GetUpstreamResult, error)
}

type RawAliasRef struct {
	ID          string
	Aliases     []string
	IsWithdrawn bool
}

type RawUpstreamRef struct {
	ID        string
	Upstreams []string
}

type RawRelatedRef struct {
	ID          string
	RelatedIDs  []string
	IsWithdrawn bool
}

type AliasGroup struct {
	VulnIDs  []string
	Modified time.Time
}

type UpstreamGroup struct {
	VulnID            string
	UpstreamIDs       []string
	Modified          time.Time
	UpstreamHierarchy []byte
}

type RelatedGroup struct {
	VulnID     string
	RelatedIDs []string
	Modified   time.Time
}

//nolint:interfacebloat
type RelationsComputationStore interface {
	// ListRawAliases streams all vulnerabilities that define raw aliases.
	ListRawAliases(ctx context.Context, handle func(ref RawAliasRef)) error

	// ListRawUpstreams streams all vulnerabilities that define raw upstreams.
	ListRawUpstreams(ctx context.Context, handle func(ref RawUpstreamRef)) error

	// ListRawRelated streams all vulnerabilities that define raw related IDs.
	ListRawRelated(ctx context.Context, handle func(ref RawRelatedRef)) error

	// GetAliasAllowAndDenyLists retrieves allowlist and denylist entries.
	GetAliasAllowAndDenyLists(ctx context.Context) (allowList map[string]struct{}, denyList map[string]struct{}, err error)

	// FetchAliasGroups streams all existing AliasGroup entities.
	FetchAliasGroups(ctx context.Context, handle func(id string, group AliasGroup)) error
	// SaveAliasGroup puts an AliasGroup entity into the store.
	SaveAliasGroup(ctx context.Context, group *AliasGroup) error
	// DeleteAliasGroup deletes an AliasGroup entity from the store.
	DeleteAliasGroup(ctx context.Context, id string) error

	// FetchUpstreamGroups streams all existing UpstreamGroup entities.
	FetchUpstreamGroups(ctx context.Context, handle func(id string, group UpstreamGroup)) error
	// SaveUpstreamGroup puts an UpstreamGroup entity into the store.
	SaveUpstreamGroup(ctx context.Context, group *UpstreamGroup) error
	// DeleteUpstreamGroup deletes an UpstreamGroup entity from the store.
	DeleteUpstreamGroup(ctx context.Context, id string) error

	// FetchRelatedGroups streams all existing RelatedGroup entities.
	FetchRelatedGroups(ctx context.Context, handle func(id string, group RelatedGroup)) error
	// SaveRelatedGroup puts a RelatedGroup entity into the store.
	SaveRelatedGroup(ctx context.Context, group *RelatedGroup) error
	// DeleteRelatedGroup deletes a RelatedGroup entity from the store.
	DeleteRelatedGroup(ctx context.Context, id string) error
}
