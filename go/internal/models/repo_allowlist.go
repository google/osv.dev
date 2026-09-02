// Package models contains the domain types for the OSV database.
package models

import "context"

// RepoAllowListFlags holds boolean feature flags for repository git analysis.
type RepoAllowListFlags struct {
	ConsiderAllBranches   bool
	CherrypicksIntroduced bool
	CherrypicksFixed      bool
	CherrypicksLimit      bool
}

// RepoAllowListStore is the repository allowlist store for repository configuration overrides.
type RepoAllowListStore interface {
	// GetFlags returns the combined feature flags for the given repository URL.
	GetFlags(ctx context.Context, repoURL string) (RepoAllowListFlags, error)
}
