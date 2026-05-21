// Package main implements the native developer server orchestrator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/google/osv.dev/go/internal/api"
	"github.com/google/osv.dev/go/logger"
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
		go func() {
			if err := api.RunServer(ctx, *backendPort); err != nil {
				logger.ErrorContext(ctx, "Go API server exited", "error", err)
			}
		}()
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
