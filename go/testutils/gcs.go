package testutils

import (
	"bytes"
	"context"
	"io"
	"iter"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv.dev/go/osv/clients"
)

// mockObject stores the data and metadata for a simulated GCS object.
type mockObject struct {
	data       []byte
	generation int64
	customTime time.Time
}

// MockStorage implements osv.CloudStorage for testing.
type MockStorage struct {
	mu      sync.RWMutex
	objects map[string]*mockObject // object path -> object data
}

// NewMockStorage creates a new mock storage client.
func NewMockStorage() *MockStorage {
	return &MockStorage{
		objects: make(map[string]*mockObject),
	}
}

func (c *MockStorage) ReadObject(ctx context.Context, path string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	obj, ok := c.objects[path]
	if !ok {
		return nil, clients.ErrNotFound
	}

	// Return copies to prevent race conditions if the caller modifies the slice.
	dataCopy := make([]byte, len(obj.data))
	copy(dataCopy, obj.data)

	return dataCopy, nil
}

func (c *MockStorage) ReadObjectAttrs(ctx context.Context, path string) (*clients.Attrs, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	obj, ok := c.objects[path]
	if !ok {
		return nil, clients.ErrNotFound
	}

	return &clients.Attrs{Generation: obj.generation, CustomTime: obj.customTime}, nil
}

// mockWriter implements io.WriteCloser for the mock storage.
type mockWriter struct {
	client *MockStorage
	path   string
	opts   *clients.WriteOptions
	buf    bytes.Buffer
}

func (w *mockWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *mockWriter) Close() error {
	return w.client.commitWrite(w.path, w.buf.Bytes(), w.opts)
}

func (c *MockStorage) NewWriter(ctx context.Context, path string, opts *clients.WriteOptions) (io.WriteCloser, error) {
	return &mockWriter{
		client: c,
		path:   path,
		opts:   opts,
	}, nil
}

// commitWrite is the internal method that performs the transactional write.
func (c *MockStorage) commitWrite(path string, data []byte, opts *clients.WriteOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	existingObj, exists := c.objects[path]

	if opts != nil && opts.IfGenerationMatches != nil {
		if *opts.IfGenerationMatches != 0 && (!exists || existingObj.generation != *opts.IfGenerationMatches) {
			return clients.ErrPreconditionFailed
		}
		if *opts.IfGenerationMatches == 0 && exists {
			return clients.ErrPreconditionFailed
		}
	}

	newGeneration := int64(1)
	if exists {
		newGeneration = existingObj.generation + 1
	}

	var customTime time.Time
	if opts != nil && opts.CustomTime != nil {
		customTime = *opts.CustomTime
	}

	// Data is already copied by bytes.Buffer
	c.objects[path] = &mockObject{
		data:       data,
		generation: newGeneration,
		customTime: customTime,
	}

	return nil
}

func (c *MockStorage) Objects(ctx context.Context, prefix string) iter.Seq2[string, error] {
	// Create a snapshot of the keys to iterate over, so we don't hold the lock.
	c.mu.RLock()
	var keys []string
	for path := range c.objects {
		if strings.HasPrefix(path, prefix) {
			keys = append(keys, path)
		}
	}
	c.mu.RUnlock()
	slices.Sort(keys) // Sort for deterministic tests.

	return func(yield func(string, error) bool) {
		for _, key := range keys {
			if !yield(key, nil) {
				return
			}
		}
	}
}

func (c *MockStorage) Close() error {
	return nil
}