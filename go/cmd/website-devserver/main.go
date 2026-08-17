// Package main implements the entry point for the OSV website development server.
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
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/internal/website"
	"github.com/google/osv.dev/go/logger"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	staticDirFlag := flag.String("static-dir", "../website/dist", "Path to static asset directory (dist)")
	docsDirFlag := flag.String("docs-dir", "../docs", "Path to documentation directory")
	dataDirFlag := flag.String("data-dir", "cmd/website-devserver/testdata", "Path to mock vulnerabilities data directory")
	sourcesFileFlag := flag.String("sources-file", "../source.yaml", "Path to source.yaml definitions")
	portFlag := flag.Int("port", 8000, "Port to listen on (overridden by PORT env var if set)")
	apiURLFlag := flag.String("api-url", "api.osv.dev", "API URL to use for links")
	flag.Parse()

	port := *portFlag
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			port = p
		}
	}

	staticDir := *staticDirFlag
	if _, err := os.Stat(staticDir); err != nil {
		if _, err := os.Stat("dist"); err == nil {
			staticDir = "dist"
		}
	}

	dataDir := *dataDirFlag
	if _, err := os.Stat(dataDir); err != nil {
		// Fallback to testdata or ../gcp/website/testdata/osv
		if _, err := os.Stat("testdata"); err == nil {
			dataDir = "testdata"
		} else if _, err := os.Stat("../gcp/website/testdata/osv"); err == nil {
			dataDir = "../gcp/website/testdata/osv"
		}
	}

	sourcesFile := *sourcesFileFlag
	if _, err := os.Stat(sourcesFile); err != nil {
		if _, err := os.Stat(filepath.Join(dataDir, "sources.yaml")); err == nil {
			sourcesFile = filepath.Join(dataDir, "sources.yaml")
		} else if _, err := os.Stat("testdata/sources.yaml"); err == nil {
			sourcesFile = "testdata/sources.yaml"
		} else {
			sourcesFile = ""
		}
	}

	staticFS := os.DirFS(staticDir)
	docsFS := os.DirFS(*docsDirFlag)

	devStore, err := NewDevStore(dataDir, sourcesFile)
	if err != nil {
		return fmt.Errorf("failed to initialize dev store: %w", err)
	}

	stores := website.Stores{
		Vuln:       devStore,
		Relations:  devStore,
		SourceRepo: devStore,
		VulnSearch: devStore,
		Linter:     devStore,
		Triage:     devStore,
	}

	srv, err := website.NewServer(website.Config{
		StaticFS: staticFS,
		DocsFS:   docsFS,
		Stores:   stores,
		APIURL:   *apiURLFlag,
		Auth: website.AuthConfig{
			BypassOAuth: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create website server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		url := fmt.Sprintf("http://localhost:%d", port)
		logger.InfoContext(ctx, "Starting website development server at "+url,
			slog.String("url", url),
			slog.Int("port", port),
			slog.String("data_dir", dataDir),
			slog.String("static_dir", staticDir),
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.InfoContext(ctx, "Shutting down website development server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}
