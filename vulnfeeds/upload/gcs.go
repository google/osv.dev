package upload

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// ToGCS uploads data from an io.Reader to a GCS bucket.
func ToGCS(ctx context.Context, bkt *storage.BucketHandle, objectName string, data io.Reader) error {
	obj := bkt.Object(objectName)
	wc := obj.NewWriter(ctx)

	if _, err := io.Copy(wc, data); err != nil {
		if closeErr := wc.Close(); closeErr != nil {
			return fmt.Errorf("failed to write to GCS object %q: %w (also failed to close writer: %v)", objectName, err, closeErr)
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

	return ToGCS(ctx, bkt, objectName, f)
}

// DownloadBucket downloads all objects from a GCS bucket to a local directory.
func DownloadBucket(ctx context.Context, bkt *storage.BucketHandle, prefix string, destDir string) error {
	it := bkt.Objects(ctx, &storage.Query{Prefix: prefix})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("bucket.Objects: %w", err)
		}

		// Skip directories
		if attrs.Name[len(attrs.Name)-1] == '/' {
			continue
		}

		destPath := filepath.Join(destDir, attrs.Name)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("os.MkdirAll: %w", err)
		}

		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("os.Create: %w", err)
		}

		rc, err := bkt.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			f.Close()
			return fmt.Errorf("Object(%q).NewReader: %w", attrs.Name, err)
		}

		if _, err := io.Copy(f, rc); err != nil {
			rc.Close()
			f.Close()
			return fmt.Errorf("io.Copy: %w", err)
		}

		rc.Close()
		f.Close()
	}

	return nil
}
