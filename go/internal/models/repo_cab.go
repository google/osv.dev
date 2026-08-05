// Package models contains the domain types for the OSV database.
package models

import "context"

// RepoCABStore is the repository allowlist store for the Consider All Branches (CAB) feature.
type RepoCABStore interface {
	// ShouldConsiderAllBranches returns true if the repository URL matches the consider all branches (CAB) allowlist.
	ShouldConsiderAllBranches(ctx context.Context, repoURL string) (bool, error)
}
