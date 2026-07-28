// Package gitter provides a client interface and HTTP client implementation for the gitter caching service.
package gitter

import (
	"context"
	"errors"
	"io"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
)

var (
	ErrRepoInaccessible = errors.New("repository is inaccessible (forbidden)")
	ErrRepoNotFound     = errors.New("repository could not be found")
	ErrInvalidInput     = errors.New("invalid request payload or query parameters")
	ErrInternalService  = errors.New("gitter service encountered an internal failure")
)

// Client exposes the capability contract of Gitter.
type Client interface {
	// GetGit streams down a compressed tarball archive of the target repository.
	GetGit(ctx context.Context, repoURL string, forceUpdate bool) (io.ReadCloser, error)

	// Cache triggers proactive caching of a target repository.
	Cache(ctx context.Context, repoURL string) error

	// GetTags returns the full list of tags/refs mapped to their commit hashes.
	GetTags(ctx context.Context, repoURL string) (*pb.TagsResponse, error)

	// GetAffectedCommits resolves equivalent/affected scope ranges (cherry-picks).
	GetAffectedCommits(ctx context.Context, req *pb.AffectedCommitsRequest) (*pb.AffectedCommitsResponse, error)

	// GetFileDiffs retrieves the tree changes since the last synced commit.
	GetFileDiffs(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error)

	// GetFileContent retrieves the raw, uncompressed content of a single file path.
	GetFileContent(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error)
}
