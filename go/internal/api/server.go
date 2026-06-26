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

	HealthCheckInterval  time.Duration
	HealthCheckThreshold int
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

	// Start background dependency health monitor
	go monitorDatabaseHealth(ctx, healthServer, opts.VulnStore, opts.HealthCheckInterval, opts.HealthCheckThreshold)

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

// monitorDatabaseHealth runs a background loop to passively monitor critical backend dependencies (Datastore, GCS, Batcher)
// and updates the gRPC serving status. It runs at the configured interval and requires a configured number of consecutive
// failures to mark the server as unhealthy, preventing transient network noise from causing false-positive outages.
func monitorDatabaseHealth(ctx context.Context, healthServer *health.Server, store models.VulnerabilityStore, interval time.Duration, threshold int) {
	if interval <= 0 {
		interval = 10 * time.Second // Sensible default
	}
	if threshold <= 0 {
		threshold = 3 // Sensible default
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Default to SERVING on startup
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := store.Ping(pingCtx)
			cancel()

			if err != nil {
				consecutiveFailures++
				logger.ErrorContext(ctx, "Dependency health check failed", "error", err, "failures", consecutiveFailures)

				if consecutiveFailures >= threshold {
					healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
				}
			} else {
				if consecutiveFailures > 0 {
					logger.InfoContext(ctx, "Dependency health restored")
				}
				consecutiveFailures = 0
				healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
			}
		}
	}
}
