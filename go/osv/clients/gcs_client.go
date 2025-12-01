// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clients

import (
	"context"
	"errors"
	"io"
	"iter"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

const numRetries = 3

// GCSClient is a concrete implementation of CloudStorage for Google Cloud Storage.
type GCSClient struct {
	client *storage.Client
	bucket *storage.BucketHandle
}

// NewGCSClient creates a new GCSClient.
func NewGCSClient(client *storage.Client, bucketName string) *GCSClient {
	bucket := client.Bucket(bucketName)
	return &GCSClient{client: client, bucket: bucket}
}

func (c *GCSClient) ReadObject(ctx context.Context, path string) ([]byte, error) {
	obj := c.bucket.Object(path)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, ErrNotFound
		}

		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (c *GCSClient) ReadObjectAttrs(ctx context.Context, path string) (*Attrs, error) {
	obj := c.bucket.Object(path)
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	return &Attrs{Generation: attrs.Generation, CustomTime: attrs.CustomTime}, nil
}

func (c *GCSClient) WriteObject(ctx context.Context, path string, data []byte, opts *WriteOptions) error {
	var err error
	for i := range numRetries {
		if i > 0 {
			// Exponential backoff: 1s, 2s, 4s
			time.Sleep(time.Duration(1<<(i-1)) * time.Second)
		}
		err = c.writeObjectOnce(ctx, path, data, opts)
		if err == nil {
			return nil
		}
		// Check if error is not transient and should not be retried
		var apiErr *googleapi.Error
		if !errors.As(err, &apiErr) || (apiErr.Code < 500 && apiErr.Code != 429) {
			return err
		}
	}

	return err
}

func (c *GCSClient) writeObjectOnce(ctx context.Context, path string, data []byte, opts *WriteOptions) error {
	obj := c.bucket.Object(path)

	if opts != nil && opts.IfGenerationMatches != nil {
		// Use generation matching to ensure we don't overwrite the object
		// if it has been modified by another process since we last read it.
		// If the conditions are not met, the write will fail.
		conds := storage.Conditions{GenerationMatch: *opts.IfGenerationMatches}
		if *opts.IfGenerationMatches == 0 {
			conds = storage.Conditions{DoesNotExist: true}
		}
		obj = obj.If(conds)
	}

	writer := obj.NewWriter(ctx)
	if opts != nil {
		if opts.CustomTime != nil {
			writer.CustomTime = *opts.CustomTime
		}
		if opts.ContentType != "" {
			writer.ContentType = opts.ContentType
		}
	}

	if _, err := writer.Write(data); err != nil {
		return err
	}

	return writer.Close()
}

func (c *GCSClient) Close() error {
	return c.client.Close()
}

func (c *GCSClient) Objects(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		it := c.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
		for {
			attrs, err := it.Next()
			if err != nil {
				if !errors.Is(err, iterator.Done) {
					yield("", err)
				}

				return
			}
			if !yield(attrs.Name, nil) {
				return
			}
		}
	}
}
