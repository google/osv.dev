package api

import (
	"context"
	"log/slog"
	"math"

	"github.com/google/osv.dev/go/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	pb "osv.dev/bindings/go/api"
)

func (s *server) ImportFindings(ctx context.Context, params *pb.ImportFindingsParameters) (*pb.ImportFindingList, error) {
	source := params.GetSource()
	if source == "" {
		return nil, status.Error(codes.InvalidArgument, "source is required")
	}
	if s.verboseLogs {
		logger.InfoContext(ctx, "checking import findings", slog.String("source", source))
	}
	findings, err := s.importFindingsStore.ListAllFromSource(ctx, source)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list import findings: %v", err)
	}

	result := new(pb.ImportFindingList)
	result.InvalidRecords = make([]*pb.ImportFinding, 0, len(findings))
	for _, finding := range findings {
		protoRecord := &pb.ImportFinding{
			BugId:       finding.BugID,
			Source:      finding.Source,
			FirstSeen:   timestamppb.New(finding.FirstSeen),
			LastAttempt: timestamppb.New(finding.LastAttempt),
			Findings:    make([]pb.ImportFindingType, len(finding.Findings)),
		}
		for i, f := range finding.Findings {
			if f > math.MaxInt32 || f < math.MinInt32 {
				f = -1
			}
			//nolint:gosec // G115: f is checked to be within int32 range above
			protoRecord.Findings[i] = pb.ImportFindingType(f)
		}
		result.InvalidRecords = append(result.InvalidRecords, protoRecord)
	}

	return result, nil
}
