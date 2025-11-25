// Copyright 2025 Google LLC
//
// Licensed under the Apache-Version 2.0 (the "License");
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

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// GCSClient is a concrete implementation of CloudStorage for Google Cloud Storage.
type GCSClient struct {
	bucket *storage.BucketHandle
}

// NewGCSClient creates a new GCSClient.
func NewGCSClient(client *storage.Client, bucketName string) *GCSClient {
	bucket := client.Bucket(bucketName)
	return &GCSClient{bucket: bucket}
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

func (c *GCSClient) NewWriter(ctx context.Context, path string, opts *WriteOptions) (io.WriteCloser, error) {
	obj := c.bucket.Object(path)

	if opts != nil && opts.IfGenerationMatches != nil {
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

	return &gcsWriter{Writer: writer}, nil
}

type gcsWriter struct {
	*storage.Writer
}

func (w *gcsWriter) Close() error {
	err := w.Writer.Close()
	if err != nil {
		var googleErr *googleapi.Error
		if errors.As(err, &googleErr) && googleErr.Code == 412 {
			return ErrPreconditionFailed
		}
		return err
	}
	return nil
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
