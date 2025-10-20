package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
)

type writeMsg struct {
	path     string
	mimeType string
	data     []byte
}

func writer(ctx context.Context, cancel context.CancelFunc, inCh <-chan writeMsg, bucket *storage.BucketHandle, pathPrefix string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case msg, ok := <-inCh:
			if !ok {
				// Channel closed.
				return
			}
			path := filepath.Join(pathPrefix, msg.path)
			if bucket != nil {
				// Write to the bucket.
				obj := bucket.Object(path)
				w := obj.NewWriter(ctx)
				w.ContentType = msg.mimeType
				r := bytes.NewReader(msg.data)
				if _, err := io.Copy(w, r); err != nil {
					logger.Error("failed to write file", slog.String("path", path), slog.Any("err", err))
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
