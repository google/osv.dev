package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/api/iterator"
)

// LinterStore implements models.LinterStore backed by a Google Cloud Storage bucket.
type LinterStore struct {
	bucket *storage.BucketHandle
	prefix string
}

var _ models.LinterStore = (*LinterStore)(nil)

// NewLinterStore creates a new GCS-backed LinterStore.
func NewLinterStore(bucket *storage.BucketHandle, prefix string) *LinterStore {
	if prefix == "" {
		prefix = "linter-result/"
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return &LinterStore{
		bucket: bucket,
		prefix: prefix,
	}
}

// ListSources lists all source directories with linter findings under the prefix.
func (s *LinterStore) ListSources(ctx context.Context) ([]string, error) {
	it := s.bucket.Objects(ctx, &storage.Query{
		Prefix:    s.prefix,
		Delimiter: "/",
	})

	var sources []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list linter sources: %w", err)
		}
		if attrs.Prefix != "" {
			src := strings.TrimPrefix(attrs.Prefix, s.prefix)
			src = strings.TrimSuffix(src, "/")
			if src != "" {
				sources = append(sources, src)
			}
		}
	}

	slices.Sort(sources)

	return sources, nil
}

// GetFindings downloads the result.json findings file for the specified source.
func (s *LinterStore) GetFindings(ctx context.Context, source string) ([]byte, error) {
	if source == "" || source == "." || strings.Contains(source, "/") || strings.Contains(source, "..") {
		return nil, models.ErrNotFound
	}

	objPath := path.Join(s.prefix, source, "result.json")
	r, err := s.bucket.Object(objPath).NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open linter findings for %q: %w", source, err)
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read linter findings for %q: %w", source, err)
	}

	return data, nil
}
