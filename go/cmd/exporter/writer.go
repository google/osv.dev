package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

// writeMsg holds the data for a file to be written.
type writeMsg struct {
	path     string
	mimeType string
	data     []byte
}

// writer is a worker that receives writeMsgs and writes them to either a GCS
// bucket or a local directory.
func writer(ctx context.Context, cancel context.CancelFunc, inCh <-chan writeMsg, client clients.CloudStorage, pathPrefix string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case msg, ok := <-inCh:
			if !ok {
				// Channel closed.
				return
			}
			path := filepath.Join(pathPrefix, msg.path)
			if client != nil {
				// Write to the bucket.
				w, err := client.NewWriter(ctx, path, &clients.WriteOptions{
					ContentType: msg.mimeType,
				})
				if err != nil {
					logger.Error("failed to create writer", slog.String("path", path), slog.Any("err", err))
					cancel()
					break
				}
				if _, err := w.Write(msg.data); err != nil {
					logger.Error("failed to write file", slog.String("path", path), slog.Any("err", err))
					_ = w.Close()
					cancel()
					break
				}
				if err := w.Close(); err != nil {
					logger.Error("failed closing file", slog.String("path", path), slog.Any("err", err))
					cancel()
					break
				}
			} else {
				// Write locally.
				dir := filepath.Dir(path)
				if err := os.MkdirAll(dir, 0755); err != nil {
					logger.Error("failed to create directories", slog.String("dir", dir), slog.Any("err", err))
					cancel()

					break
				}
				if err := os.WriteFile(path, msg.data, 0600); err != nil {
					logger.Error("failed to write file", slog.String("path", path), slog.Any("err", err))
					cancel()

					break
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
