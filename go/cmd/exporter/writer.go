package main

import (
	"context"
	"errors"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

// crc32cTable uses the Castagnoli polynomial, matching GCS's own checksum algorithm.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

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
				// Skip the upload if the object already has the same content.
				if gcsContentUnchanged(ctx, client, path, msg.data) {
					break
				}
				err := client.WriteObject(ctx, path, msg.data, &clients.WriteOptions{
					ContentType: msg.mimeType,
				})
				if err != nil {
					logger.Error("failed to write file", slog.String("path", path), slog.Any("err", err))
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

// gcsContentUnchanged returns true if the object at path already has the same
// CRC32C checksum as data, meaning the upload would be a no-op. Any error
// reading the object's attributes (other than ErrNotFound) is logged and
// treated as "content changed" so the upload proceeds.
func gcsContentUnchanged(ctx context.Context, client clients.CloudStorage, path string, data []byte) bool {
	attrs, err := client.ReadObjectAttrs(ctx, path)
	if err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "failed to read object attrs, proceeding with upload", slog.String("path", path), slog.Any("err", err))
		}

		return false
	}
	if attrs.CRC32C == crc32.Checksum(data, crc32cTable) {
		logger.InfoContext(ctx, "skipping upload, content unchanged", slog.String("path", path))

		return true
	}

	return false
}
