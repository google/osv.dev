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

	staticFiles, err := getStaticFS(*staticDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load static filesystem", slog.String("dir", *staticDir), slog.Any("error", err))

		return fmt.Errorf("failed to load static filesystem %q: %w", *staticDir, err)
	}

	docsFiles, err := getDocsFS(*docsDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load docs filesystem", slog.String("dir", *docsDir), slog.Any("error", err))

		return fmt.Errorf("failed to load docs filesystem %q: %w", *docsDir, err)
	}

	srv, err := website.NewServer(website.Config{
		StaticFS: staticFiles,
		DocsFS:   docsFiles,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create website server", slog.Any("error", err))

		return fmt.Errorf("failed to create website server: %w", err)
	}

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
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		logger.InfoContext(shutdownCtx, "Shutting down website server...")
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(shutdownCtx, "Error during server shutdown", slog.Any("error", err))

			return err
		}
	}

	return nil
}
