// Package metrics provides Prometheus metric definitions and exposition for OSV services.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultPort is the standard metrics port scraped by GMP.
const DefaultPort = "9090"

// Server wraps an HTTP server exposing Prometheus metrics.
type Server struct {
	httpServer *http.Server
}

// NewServer creates a new metrics server on the given address.
func NewServer(addr string) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// Handler returns the underlying http.Handler.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Start runs the metrics server in a background goroutine and gracefully shuts down when ctx is done.
func (s *Server) Start(ctx context.Context) {
	go func() {
		logger.InfoContext(ctx, "Starting Prometheus metrics server on "+s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.ErrorContext(ctx, "Metrics server error", slog.Any("error", err))
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(ctx, "Failed to gracefully shutdown metrics server", slog.Any("error", err))
		}
	}()
}

// StartMetricsServer is a convenience function that starts a metrics server on ":port"
// using DefaultPort if port is empty.
func StartMetricsServer(ctx context.Context, port string) *Server {
	if port == "" {
		port = DefaultPort
	}
	addr := ":" + port
	srv := NewServer(addr)
	srv.Start(ctx)

	return srv
}
