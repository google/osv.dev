// Package gcs provides utilities for working with Google Cloud Storage.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

const (
	hashMetadataKey = "sha256-hash" // hashMetadataKey is the key for the sha256 hash in the GCS object metadata.
)

type Helper struct {
	wg     sync.WaitGroup
	bus    chan *uploadMsg
	bkt    *storage.BucketHandle
	client *storage.Client
	once   sync.Once
}

type uploadMsg struct {
	objectName  string
	data        io.Reader
	contentType string
	hash        string // if hash is empty, always upload
}

func InitUploadPool(ctx context.Context, workers int, bktName string) (*Helper, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}

	helper := &Helper{
		bus:    make(chan *uploadMsg, workers),
		bkt:    client.Bucket(bktName),
		client: client,
	}

	for range workers {
		helper.wg.Add(1)
		go bucketWorker(ctx, helper)
	}

	return helper, nil
}

func bucketWorker(ctx context.Context, gcsHelper *Helper) {
	defer gcsHelper.wg.Done()
	for msg := range gcsHelper.bus {
		func() {
			if closer, ok := msg.data.(io.Closer); ok {
				defer closer.Close()
			}
			if msg.hash != "" {
				attrs, err := gcsHelper.bkt.Object(msg.objectName).Attrs(ctx)
				if err == nil {
					if attrs.Metadata != nil && attrs.Metadata[hashMetadataKey] == msg.hash {
						logger.Info("Skipping GCS upload, hash matches", slog.String("id", msg.objectName))
						return
					}
				} else if !errors.Is(err, storage.ErrObjectNotExist) {
					logger.Info("Failed to get object attributes", slog.String("object", msg.objectName), slog.String("error", err.Error()))
					return
				}
			}
			var metadata map[string]string
			if msg.hash != "" {
				metadata = map[string]string{hashMetadataKey: msg.hash}
			}
			if err := UploadToGCS(ctx, gcsHelper.bkt, msg.objectName, msg.data, msg.contentType, metadata); err != nil {
				logger.Info("Failed to upload object", slog.String("object", msg.objectName), slog.String("error", err.Error()))
			}

			logger.Info("Uploaded GCS object", slog.String("object", msg.objectName))
		}()
	}
}

func (g *Helper) Upload(objectName string, data io.Reader, hash string, contentType string) {
	g.bus <- &uploadMsg{
		objectName:  objectName,
		data:        data,
		hash:        hash,
		contentType: contentType,
	}
}

func (g *Helper) CloseAndWait() {
	g.once.Do(func() {
		close(g.bus)
		g.wg.Wait()
		if g.client != nil {
			g.client.Close()
		}
	})
}

// UploadToGCS uploads data from an io.Reader to a GCS bucket.
func UploadToGCS(ctx context.Context, bkt *storage.BucketHandle, objectName string, data io.Reader, contentType string, metadata map[string]string) error {
	obj := bkt.Object(objectName)
	wc := obj.NewWriter(ctx)
	if contentType != "" {
		wc.ContentType = contentType
	}
	if metadata != nil {
		wc.Metadata = metadata
	}

	if _, err := io.Copy(wc, data); err != nil {
		if closeErr := wc.Close(); closeErr != nil {
			return fmt.Errorf("failed to write to GCS object %q: %w (also failed to close writer: %w)", objectName, err, closeErr)
		}

		return fmt.Errorf("failed to write to GCS object %q: %w", objectName, err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer for object %q: %w", objectName, err)
	}

	return nil
}

// UploadFile uploads a local file to a GCS bucket.
func UploadFile(ctx context.Context, bkt *storage.BucketHandle, objectName string, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("os.Open: %w", err)
	}
	defer f.Close()

	return UploadToGCS(ctx, bkt, objectName, f, "", nil)
}

// DownloadBucket downloads all objects from a GCS bucket to a local directory.
func DownloadBucket(ctx context.Context, bkt *storage.BucketHandle, prefix string, destDir string) error {
	it := bkt.Objects(ctx, &storage.Query{Prefix: prefix})

	g, ctx := errgroup.WithContext(ctx)
	// Limit concurrency to avoid running out of file descriptors or overwhelming the network
	g.SetLimit(10)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("bucket.Objects: %w", err)
		}

		// Skip directories
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}

		destPath := filepath.Join(destDir, attrs.Name)
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid object name %q: path traversal attempt", attrs.Name)
		}

		// Capture loop variable for the goroutine
		objName := attrs.Name

		g.Go(func() error {
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("os.MkdirAll: %w", err)
			}

			f, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("os.Create: %w", err)
			}
			defer f.Close()

			rc, err := bkt.Object(objName).NewReader(ctx)
			if err != nil {
				return fmt.Errorf("Object(%q).NewReader: %w", objName, err)
			}
			defer rc.Close()

			if _, err := io.Copy(f, rc); err != nil {
				return fmt.Errorf("io.Copy: %w", err)
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

// listBucketObjects lists the names of all objects in a Google Cloud Storage bucket.
// It does not download the file contents.
func ListBucketObjects(ctx context.Context, bucket *storage.BucketHandle, prefix string) ([]string, error) {
	it := bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var filenames []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break // All objects have been listed.
		}
		if err != nil {
			return nil, fmt.Errorf("bucket.Objects: %w", err)
		}
		filenames = append(filenames, attrs.Name)
	}

	return filenames, nil
}
