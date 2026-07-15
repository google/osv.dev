// Package main implements the entry point for the OSV website server in Go.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/internal/website"
	"github.com/google/osv.dev/go/logger"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	defaultPort := 8000
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			defaultPort = p
		} else {
			logger.ErrorContext(ctx, "Invalid PORT environment variable, using default", slog.Any("error", err))
		}
	}

	port := flag.Int("port", defaultPort, "port for the website server")
	staticDir := flag.String("static-dir", "dist", "directory containing static assets")
	docsDir := flag.String("docs-dir", "docs", "directory containing API docs")
	flag.Parse()

	var staticFS website.Config
	if *staticDir != "" {
		staticFS.StaticFS = os.DirFS(*staticDir)
	}
	if *docsDir != "" {
		staticFS.DocsFS = os.DirFS(*docsDir)
	}

	srv := website.NewServer(staticFS)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		url := fmt.Sprintf("http://localhost:%d", *port)
		logger.InfoContext(ctx, "Starting OSV website server at "+url, slog.Int("port", *port), slog.String("url", url))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		logger.ErrorContext(ctx, "Server error", slog.Any("error", err))
		return err
	case <-ctx.Done():
		logger.InfoContext(ctx, "Shutting down website server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(ctx, "Error during server shutdown", slog.Any("error", err))
			return err
		}
	}

	return nil
}
