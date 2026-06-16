// Package main implements the native developer server orchestrator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/api"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

const (
	defaultESPPort     = 8080
	defaultBackendPort = 8000
	dockerImage        = "osv/esp:latest"
	containerName      = "osv-esp"
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

	espPort := flag.Int("port", defaultESPPort, "ESP listener port")
	backendPort := flag.Int("backend-port", defaultBackendPort, "Backend server port")
	credPath := flag.String("cred", "", "Path to GCP Service Account credential JSON (defaults to local Application Default Credentials)")
	noBackend := flag.Bool("no-backend", false, "Start ESPv2 without launching the Go API backend server")
	flag.Parse()

	// Auto-discover Application Default Credentials (ADC)
	if *credPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			adcPath := filepath.Join(home, ".config/gcloud/application_default_credentials.json")
			if _, err := os.Stat(adcPath); err == nil {
				*credPath = adcPath
			}
		}
	}

	if *credPath == "" {
		err := errors.New("path to GCP Service Account credential JSON file is required (please run 'gcloud auth application-default login' or specify via -cred)")
		logger.ErrorContext(ctx, err.Error())

		return err
	}

	// Stop any orphaned container from a previous run
	_ = exec.CommandContext(ctx, "docker", "stop", containerName).Run()

	if !*noBackend {
		logger.InfoContext(ctx, "Starting Go API backend natively", "port", *backendPort)
		go runBackend(ctx, *backendPort)
	}

	logger.InfoContext(ctx, "Starting ESPv2 container", "port", *espPort, "backendPort", *backendPort)

	credDir := filepath.Dir(*credPath)
	credName := filepath.Base(*credPath)

	dockerArgs := []string{
		"run",
		"--name", containerName,
		"--network=host",
		"--rm",
		"-v", credDir + ":/esp:ro",
		fmt.Sprintf("--publish=%d", *espPort),
		dockerImage,
		"--disable_tracing",
		"--service=api-test.osv.dev",
		"--rollout_strategy=managed",
		"--underscores_in_headers",
		fmt.Sprintf("--listener_port=%d", *espPort),
		fmt.Sprintf("--backend=grpc://localhost:%d", *backendPort),
		"--service_account_key=/esp/" + credName,
		"--non_gcp",
		"--enable_debug",
		"--transcoding_preserve_proto_field_names",
		"--envoy_connection_buffer_limit_bytes=104857600",
	}

	// Redirect ESPv2 output to esp.log to keep the console clean
	espLog, err := os.OpenFile("esp.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		err = fmt.Errorf("failed to create esp.log: %w", err)
		logger.ErrorContext(ctx, err.Error())

		return err
	}
	defer espLog.Close()

	espCmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	espCmd.Stdout = espLog
	espCmd.Stderr = espLog

	if err := espCmd.Start(); err != nil {
		err = fmt.Errorf("failed to start ESPv2: %w", err)
		logger.ErrorContext(ctx, err.Error())

		return err
	}

	defer func() {
		logger.InfoContext(ctx, "Stopping ESPv2 docker container...")
		// Use background context to ensure cleanup runs even if parent context is cancelled
		_ = exec.Command("docker", "stop", containerName).Run()
	}()

	// Wait for the ESP container to stop, or for context to be cancelled
	select {
	case err := <-runCmdAsync(espCmd):
		if err != nil {
			err = fmt.Errorf("ESPv2 exited with error: %w", err)
			logger.ErrorContext(ctx, err.Error())

			return err
		}
	case <-ctx.Done():
		logger.InfoContext(ctx, "Received termination signal, shutting down cleanly...")
	}

	return nil
}

func runCmdAsync(cmd *exec.Cmd) <-chan error {
	out := make(chan error, 1)
	go func() {
		out <- cmd.Wait()
	}()

	return out
}

func runBackend(ctx context.Context, port int) {
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		logger.ErrorContext(ctx, "GOOGLE_CLOUD_PROJECT environment variable is not set")
		return
	}
	datastoreID := os.Getenv("DATASTORE_DATABASE_ID") // empty string is the (default) database
	dbClient, err := datastore.NewClientWithDatabase(ctx, project, datastoreID)
	if err != nil {
		logger.ErrorContext(ctx, "failed to create datastore client", "error", err)
		return
	}
	defer dbClient.Close()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client", slog.Any("error", err))
		return
	}
	defer gcsClient.Close()
	vulnBucket := os.Getenv("OSV_VULNERABILITIES_BUCKET")
	if vulnBucket == "" {
		logger.ErrorContext(ctx, "OSV_VULNERABILITIES_BUCKET environment variable is not set")
		return
	}
	var batchTimeout time.Duration
	if t := os.Getenv("OSV_DB_BATCH_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			batchTimeout = d
		} else {
			logger.ErrorContext(ctx, "Invalid OSV_DB_BATCH_TIMEOUT, using default", slog.Any("error", err))
		}
	}
	var batchMaxElements int
	if m := os.Getenv("OSV_DB_BATCH_MAX_SIZE"); m != "" {
		if val, err := strconv.Atoi(m); err == nil {
			batchMaxElements = val
		} else {
			logger.ErrorContext(ctx, "Invalid OSV_DB_BATCH_MAX_SIZE, using default", slog.Any("error", err))
		}
	}

	vulnStore := db.NewVulnerabilityStore(db.VulnStoreConfig{
		Client:           dbClient,
		GCS:              clients.NewGCSClient(gcsClient, vulnBucket),
		BatchTimeout:     batchTimeout,
		BatchMaxElements: batchMaxElements,
	})
	relationsStore := db.NewRelationsStore(dbClient)
	if err := api.RunServer(ctx, api.ServerOptions{
		Port:           port,
		VerboseLogs:    true,
		VulnStore:      vulnStore,
		RelationsStore: relationsStore,
	}); err != nil {
		logger.ErrorContext(ctx, "Go API server exited", "error", err)
	}
}
