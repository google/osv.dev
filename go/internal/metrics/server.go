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

const defaultShutdownTimeout = 5 * time.Second

// StartServer starts a background HTTP server serving Prometheus /metrics and /healthz.
// It automatically shuts down when ctx is cancelled.
func StartServer(ctx context.Context, port string) {
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		logger.InfoContext(ctx, "Starting Prometheus metrics server", slog.String("port", port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.WarnContext(ctx, "Prometheus metrics server exited with error", slog.Any("err", err))
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
}
