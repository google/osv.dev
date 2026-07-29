// Package gitter provides a client interface and HTTP client implementation for the gitter caching service.
package gitter

import (
	"context"
	"errors"
	"io"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
)

// Map the HTTP status codes into Gitter-specific errors
var (
	ErrRepoInaccessible = errors.New("repository is inaccessible (forbidden)")
	ErrRepoNotFound     = errors.New("repository not found")
	ErrInvalidInput     = errors.New("invalid request payload or query parameters")
	ErrInternalService  = errors.New("gitter internal server error")
)

// Client exposes the capability contract of Gitter.
type Client interface {
	// GetGit streams down a compressed tarball archive of the target repository.
	GetGit(ctx context.Context, repoURL string, forceUpdate bool) (io.ReadCloser, error)

	// Cache triggers proactive caching of a target repository.
	Cache(ctx context.Context, repoURL string) error

	// GetTags returns the full list of tags/refs mapped to their commit hashes.
	GetTags(ctx context.Context, repoURL string) (*pb.TagsResponse, error)

	// GetAffectedCommits resolves and lists affected commits based on introduced/fixed/last_affected commit ranges.
	GetAffectedCommits(ctx context.Context, req *pb.AffectedCommitsRequest) (*pb.AffectedCommitsResponse, error)

	// GetFileDiffs retrieves the file changes since given last synced commit.
	GetFileDiffs(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error)

	// GetFileContent retrieves the raw, uncompressed content of a single file path.
	GetFileContent(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error)
}
