// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gcs provides helper utilities for Google Cloud Storage operations.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

// ListBucketObjectsQuery lists object names matching a storage query.
// It optimizes the GCS API request by retrieving only the Name attribute.
func ListBucketObjectsQuery(ctx context.Context, bucket *storage.BucketHandle, query *storage.Query) ([]string, error) {
	if query == nil {
		query = &storage.Query{}
	}
	if err := query.SetAttrSelection([]string{"Name"}); err != nil {
		return nil, fmt.Errorf("failed to set attribute selection: %w", err)
	}

	it := bucket.Objects(ctx, query)
	var filenames []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bucket.Objects: %w", err)
		}
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}
		filenames = append(filenames, attrs.Name)
	}

	return filenames, nil
}

// buildPartitionQueries constructs partitioned storage queries using StartOffset and EndOffset.
func buildPartitionQueries(globalPrefix string, breakdownPrefixes []string) []*storage.Query {
	globalPrefix = strings.TrimSuffix(globalPrefix, "/")
	globalPrefixWithSlash := ""
	if globalPrefix != "" {
		globalPrefixWithSlash = globalPrefix + "/"
	}

	if len(breakdownPrefixes) == 0 {
		return []*storage.Query{{Prefix: globalPrefixWithSlash}}
	}

	sortedBreakdowns := make([]string, len(breakdownPrefixes))
	copy(sortedBreakdowns, breakdownPrefixes)
	slices.Sort(sortedBreakdowns)

	queries := make([]*storage.Query, 0, len(sortedBreakdowns)+1)

	// 1. First query: everything before the first breakdown
	queries = append(queries, &storage.Query{
		Prefix:    globalPrefixWithSlash,
		EndOffset: globalPrefixWithSlash + sortedBreakdowns[0],
	})

	// 2. Intermediate queries: ranges between breakdowns
	for i := range len(sortedBreakdowns) - 1 {
		queries = append(queries, &storage.Query{
			Prefix:      globalPrefixWithSlash,
			StartOffset: globalPrefixWithSlash + sortedBreakdowns[i],
			EndOffset:   globalPrefixWithSlash + sortedBreakdowns[i+1],
		})
	}

	// 3. Last query: everything from the last breakdown onwards
	queries = append(queries, &storage.Query{
		Prefix:      globalPrefixWithSlash,
		StartOffset: globalPrefixWithSlash + sortedBreakdowns[len(sortedBreakdowns)-1],
	})

	return queries
}

// ObjectsFastStream returns an iterator that streams object names in parallel as they are discovered.
func ObjectsFastStream(ctx context.Context, bucket *storage.BucketHandle, globalPrefix string, breakdownPrefixes []string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		queries := buildPartitionQueries(globalPrefix, breakdownPrefixes)

		outCh := make(chan string, 100)
		g, ctx := errgroup.WithContext(ctx)

		for _, q := range queries {
			g.Go(func() error {
				if err := q.SetAttrSelection([]string{"Name"}); err != nil {
					return fmt.Errorf("failed to set attribute selection: %w", err)
				}
				it := bucket.Objects(ctx, q)
				for {
					attrs, err := it.Next()
					if errors.Is(err, iterator.Done) {
						return nil
					}
					if err != nil {
						return err
					}
					if strings.HasSuffix(attrs.Name, "/") {
						continue
					}
					select {
					case outCh <- attrs.Name:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			})
		}

		go func() {
			_ = g.Wait()
			close(outCh)
		}()

		for name := range outCh {
			if !yield(name, nil) {
				return
			}
		}

		if err := g.Wait(); err != nil {
			yield("", err)
		}
	}
}
