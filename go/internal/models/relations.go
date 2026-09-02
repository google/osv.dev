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

// Hierarchy represents a computed Directed Acyclic Graph of upstream or downstream vulnerability relationships.
type Hierarchy struct {
	Roots []string            // Root nodes where hierarchy rendering starts
	Graph map[string][]string // Adjacency map: Parent ID -> Child IDs
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
	// GetUpstreamHierarchy retrieves the computed upstream DAG for a vulnerability.
	// Returns ErrNotFound if no upstream hierarchy is available.
	GetUpstreamHierarchy(ctx context.Context, id string) (*Hierarchy, error)
	// GetDownstreamHierarchy retrieves the computed downstream DAG for a vulnerability.
	// Returns ErrNotFound if no downstream hierarchy is available.
	GetDownstreamHierarchy(ctx context.Context, id string) (*Hierarchy, error)
}

type UnimplementedRelationsStore struct{}

var _ RelationsStore = UnimplementedRelationsStore{}

func (s UnimplementedRelationsStore) GetAliases(_ context.Context, _ string) (*GetAliasResult, error) {
	panic("not implemented")
}

func (s UnimplementedRelationsStore) GetRelated(_ context.Context, _ string) (*GetRelatedResult, error) {
	panic("not implemented")
}

func (s UnimplementedRelationsStore) GetUpstream(_ context.Context, _ string) (*GetUpstreamResult, error) {
	panic("not implemented")
}

func (s UnimplementedRelationsStore) GetUpstreamHierarchy(_ context.Context, _ string) (*Hierarchy, error) {
	panic("not implemented")
}

func (s UnimplementedRelationsStore) GetDownstreamHierarchy(_ context.Context, _ string) (*Hierarchy, error) {
	panic("not implemented")
}
