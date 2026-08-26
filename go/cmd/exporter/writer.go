package main

import (
	"context"
	"errors"
	"hash/crc32"
	"io"
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
	filePath string // If set, stream from local file instead of holding data in memory
}

// writer is a worker that receives writeMsgs and writes them to either a GCS
// bucket or a local directory.
func writer(ctx context.Context, cancel context.CancelFunc, inCh <-chan writeMsg, client clients.CloudStorage, pathPrefix string, wg *sync.WaitGroup) {
	defer wg.Done()
	for msg := range inCh {
		path := filepath.Join(pathPrefix, msg.path)
		if msg.filePath != "" {
			if client != nil {
				if gcsFileUnchanged(ctx, client, path, msg.filePath) {
					continue
				}
				f, err := os.Open(msg.filePath)
				if err != nil {
					logger.Error("failed to open local file for upload", slog.String("path", path), slog.String("file", msg.filePath), slog.Any("err", err))
					cancel()

					break
				}
				err = client.WriteObjectStream(ctx, path, f, &clients.WriteOptions{
					ContentType: msg.mimeType,
				})
				f.Close()
				if err != nil {
					logger.Error("failed to stream write file", slog.String("path", path), slog.Any("err", err))
					cancel()

					break
				}
			} else {
				// Write locally: copy from msg.filePath to path
				dir := filepath.Dir(path)
				if err := os.MkdirAll(dir, 0755); err != nil {
					logger.Error("failed to create directories", slog.String("dir", dir), slog.Any("err", err))
					cancel()

					break
				}
				if err := copyFile(msg.filePath, path); err != nil {
					logger.Error("failed to copy file locally", slog.String("src", msg.filePath), slog.String("dst", path), slog.Any("err", err))
					cancel()

					break
				}
			}
		} else {
			if client != nil {
				// Skip the upload if the object already has the same content.
				if gcsContentUnchanged(ctx, client, path, msg.data) {
					continue
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
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)

	return err
}

func gcsFileUnchanged(ctx context.Context, client clients.CloudStorage, path string, filePath string) bool {
	attrs, err := client.ReadObjectAttrs(ctx, path)
	if err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "failed to read object attrs, proceeding with upload", slog.String("path", path), slog.Any("err", err))
		}

		return false
	}
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()
	h := crc32.New(crc32cTable)
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	if attrs.CRC32C == h.Sum32() {
		logger.InfoContext(ctx, "skipping upload, content unchanged", slog.String("path", path))

		return true
	}

	return false
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
