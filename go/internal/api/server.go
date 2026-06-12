// Package api implements the public gRPC server API for OSV.
package api

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	pb "osv.dev/bindings/go/api"
)

type server struct {
	pb.UnimplementedOSVServer

	verboseLogs bool

	vulnStore           models.VulnerabilityStore
	relationsStore      models.RelationsStore
	importFindingsStore models.ImportFindingsStore
	repoIndexStore      models.RepoIndexStore
	recovererPublisher  clients.Publisher

	singleQueryTimeout time.Duration
	batchQueryTimeout  time.Duration
	responseSizeLimit  int64
}

type ServerOptions struct {
	Port int
	// VerboseLogs controls whether to log verbose information,
	// including per-request data.
	VerboseLogs         bool
	VulnStore           models.VulnerabilityStore
	RelationsStore      models.RelationsStore
	ImportFindingsStore models.ImportFindingsStore
	RepoIndexStore      models.RepoIndexStore
	RecovererPublisher  clients.Publisher
}

// RunServer starts the gRPC server and handles graceful shutdown.
func RunServer(ctx context.Context, opts ServerOptions) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		logger.ErrorContext(ctx, "failed to listen", "error", err)
		return err
	}

	s := grpc.NewServer()
	pb.RegisterOSVServer(s, &server{
		vulnStore:           opts.VulnStore,
		relationsStore:      opts.RelationsStore,
		importFindingsStore: opts.ImportFindingsStore,
		repoIndexStore:      opts.RepoIndexStore,
		recovererPublisher:  opts.RecovererPublisher,
		verboseLogs:         opts.VerboseLogs,
	})

	healthServer := health.NewServer()
	healthgrpc.RegisterHealthServer(s, healthServer)

	logger.InfoContext(ctx, "server listening", "port", opts.Port)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- s.Serve(lis)
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			logger.ErrorContext(ctx, "server failed to serve", "error", err)
			return err
		}
	case <-ctx.Done():
		logger.InfoContext(ctx, "received shutdown signal, shutting down server gracefully")
		healthServer.Shutdown()
		s.GracefulStop()
		if err := <-serveErr; err != nil {
			logger.ErrorContext(ctx, "server failed during shutdown", "error", err)
			return err
		}
	}

	return nil
}
