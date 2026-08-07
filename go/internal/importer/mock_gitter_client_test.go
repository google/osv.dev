package importer

import (
	"context"
	"errors"
	"io"

	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
)

// mockGitterClient is a mock implementation of gitter.Client for unit testing importer Git operations.
// Tests can set file-diffs and file-content funcs to mock specific responses or errors.
type mockGitterClient struct {
	fileDiffsFunc   func(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error)
	fileContentFunc func(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error)
}

func (m *mockGitterClient) GetGit(_ context.Context, _ string, _ bool) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) Cache(_ context.Context, _ string) error {
	return nil
}

func (m *mockGitterClient) GetTags(_ context.Context, _ string) (*pb.TagsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetAffectedCommits(_ context.Context, _ *pb.AffectedCommitsRequest) (*pb.AffectedCommitsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetFileDiffs(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error) {
	if m.fileDiffsFunc != nil {
		return m.fileDiffsFunc(ctx, req)
	}

	return &pb.FileDiffsResponse{}, nil
}

func (m *mockGitterClient) GetFileContent(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error) {
	if m.fileContentFunc != nil {
		return m.fileContentFunc(ctx, req)
	}

	return &pb.FileContentResponse{}, nil
}

var _ gitter.Client = (*mockGitterClient)(nil)
