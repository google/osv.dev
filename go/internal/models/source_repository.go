// package models contains the domain types for the OSV database.
package models

import (
	"context"
	"iter"
	"time"
)

type SourceRepositoryType int

const (
	SourceRepositoryTypeGit    SourceRepositoryType = 0
	SourceRepositoryTypeBucket SourceRepositoryType = 1
	SourceRepositoryTypeREST   SourceRepositoryType = 2
)

type SourceRepository struct {
	// The name of the source.
	Name string
	// DB prefixes.
	// https://ossf.github.io/osv-schema/#id-modified-fields
	IDPrefixes []string

	// The SourceRepositoryType of the repository.
	Type   SourceRepositoryType
	Git    *SourceRepoGit
	Bucket *SourceRepoBucket
	REST   *SourceRepoREST

	// Apply strict validation (JSON Schema + linter checks) to this source.
	Strictness bool
	// Patterns of files to exclude (regex).
	IgnorePatterns []string
	// Default extension (".json", ".yaml").
	Extension string
	// Key path within each file to store the vulnerability.
	KeyPath string

	// Git Content Analysis (Applied to Git commit ranges found in vulnerabilities)
	GitAnalysis *GitAnalysisConfig

	// HTTP link prefix to individual OSV source records.
	Link string
	// HTTP link prefix to individual vulnerability records for humans.
	HumanLink string
}

type GitAnalysisConfig struct {
	// If true, don't analyze any Git ranges.
	IgnoreGit bool
	// Whether to detect cherypicks or not (slow for large repos).
	DetectCherrypicks bool
	// Whether to consider all branches when analyzing GIT ranges.
	ConsiderAllBranches bool
	// Whether to populate "affected[].versions" from Git ranges.
	VersionsFromRepo bool
}

type SourceRepoGit struct {
	// The repo URL for the source
	URL string
	// Optional branch for repo
	Branch string
	// Vulnerability data not under this path is ignored by the importer.
	Path string
	// Last synced hash.
	LastSyncedCommit string
}

type SourceRepoBucket struct {
	// Bucket name
	Bucket string
	// Vulnerability data not under this path is ignored by the importer.
	Path string
	// Last date recurring updates were requested.
	LastUpdated *time.Time
	// Ignore last import time once
	IgnoreLastImportTime bool
	// Ignore deletion threshold
	IgnoreDeletionThreshold bool
}

type SourceRepoREST struct {
	// The API endpoint
	URL string
	// Last date recurring updates were requested.
	LastUpdated *time.Time
	// Ignore last import time once.
	IgnoreLastImportTime bool
	// Ignore deletion threshold.
	IgnoreDeletionThreshold bool
}

type SourceRepositoryStore interface {
	// Get retrieves a source repository by its name.
	// Returns ErrNotFound if the repository does not exist.
	Get(ctx context.Context, name string) (*SourceRepository, error)

	// Update creates or updates a source repository.
	// The name argument must match repo.Name.
	Update(ctx context.Context, name string, repo *SourceRepository) error

	// All returns an iterator over all source repositories.
	All(ctx context.Context) iter.Seq2[*SourceRepository, error]
}
