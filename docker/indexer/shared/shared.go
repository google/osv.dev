// Package shared provides functionality that is used in multiple packages.
package shared

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
)

const TarExt = ".tar"

// CopyFromBucket copies a directory from a bucket to a temporary location.
func CopyFromBucket(ctx context.Context, bucketHdl *storage.BucketHandle, name string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	obj := bucketHdl.Object(name + TarExt)
	r, err := obj.NewReader(ctx)
	if err != nil {
		return "", err
	}
	tarRdr := tar.NewReader(r)
	for {
		hdr, err := tarRdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		buf, err := io.ReadAll(tarRdr)
		if err != nil {
			return "", err
		}
		path := filepath.Join(tmpDir, hdr.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0760); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, buf, 0660); err != nil {
			return "", err
		}
	}
	return tmpDir, nil
}
