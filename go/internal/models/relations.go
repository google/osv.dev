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
