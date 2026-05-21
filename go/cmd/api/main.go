// Package main implements the entry point for the production OSV API server.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/osv.dev/go/internal/api"
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

	port := flag.Int("port", 8000, "port for the OSV API")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return api.RunServer(ctx, *port)
}
