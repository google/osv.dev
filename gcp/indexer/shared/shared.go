/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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

const (
	TarExt = ".tar"
	Git    = "GIT"
	MD5    = "MD5"
	// Update this to force reindexing and updating of all entries with lesser version number
	LatestDocumentVersion = 2
)

// CopyFromBucket copies a directory from a bucket to a temporary location.
func CopyFromBucket(ctx context.Context, bucketHdl *storage.BucketHandle, name string) (string, error) {
	tmpDir, err := os.MkdirTemp("", name)
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
		path := filepath.Clean(filepath.Join(tmpDir, hdr.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0760); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, buf, 0660); err != nil {
			return "", err
		}
	}
	return tmpDir, nil
}
