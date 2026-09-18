package importer

import (
	"context"

	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
)

// mockGitterClient is a mock implementation of gitter.Client for unit testing importer Git operations.
// Tests can set file-diffs and file-content funcs to mock specific responses or errors.
type mockGitterClient struct {
	gitter.Client

	fileDiffsFunc   func(ctx context.Context, req *pb.FileDiffsRequest) (*pb.FileDiffsResponse, error)
	fileContentFunc func(ctx context.Context, req *pb.FileContentRequest) (*pb.FileContentResponse, error)
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
