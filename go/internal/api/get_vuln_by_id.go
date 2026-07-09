package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "osv.dev/bindings/go/api"
)

//nolint:revive // complains about 'Id' instead of 'ID', but that matches the API (the proto).
func (s *server) GetVulnById(ctx context.Context, params *pb.GetVulnByIdParameters) (*osvschema.Vulnerability, error) {
	id := params.GetId()
	if len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ID is required")
	}
	// Datastore has a limit of how large indexed properties can be (1500 bytes).
	// Vulnerability IDs are not going to be over 100 characters.
	if len(id) > 100 {
		return nil, status.Error(codes.InvalidArgument, "ID is too long")
	}
	vulnerability, err := s.vulnStore.GetFull(ctx, id)
	if err == nil {
		return vulnerability, nil
	}
	if !errors.Is(err, models.ErrNotFound) {
		if !osvutil.IsContextError(err) {
			logger.ErrorContext(ctx, "failed to get vulnerability from store",
				slog.String("id", id),
				slog.Any("error", err),
			)
		}

		return nil, status.Errorf(codes.Internal, "error getting vulnerability: %v", err)
	}

	// Check for aliases
	aliases, err := s.relationsStore.GetAliases(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "Vulnerability not found")
		}

		if !osvutil.IsContextError(err) {
			logger.ErrorContext(ctx, "failed to check aliases for vulnerability",
				slog.String("id", id),
				slog.Any("error", err),
			)
		}

		return nil, status.Errorf(codes.Internal, "error getting vulnerability: %v", err)
	}

	aliasStrs := strings.Join(aliases.Aliases, " ")

	return nil, status.Errorf(codes.NotFound, "Vulnerability not found, but the following aliases were: %s", aliasStrs)
}
