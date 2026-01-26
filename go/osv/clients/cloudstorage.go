// Copyright 2025 Google LLC
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

// Package clients provides clients for google cloud services.
package clients

import (
	"context"
	"errors"
	"iter"
	"time"
)

var (
	// ErrNotFound is returned when a storage object is not found.
	ErrNotFound = errors.New("object not found")
	// ErrPreconditionFailed is returned when a generation precondition fails.
	ErrPreconditionFailed = errors.New("precondition failed")
)

// WriteOptions specifies options for a write operation.
type WriteOptions struct {
	// IfGenerationMatches is a precondition. The write will only succeed if
	// the object's current generation matches this value.
	// If nil, no precondition is enforced.
	// If set to 0, the object must not exist.
	IfGenerationMatches *int64
	// CustomTime sets the custom time metadata on the object.
	CustomTime *time.Time
	// ContentType sets the MIME type of the object.
	ContentType string
}

// Attrs contains metadata about a storage object.
type Attrs struct {
	// Generation is the generation of the object.
	Generation int64
	// CustomTime is the custom time metadata of the object.
	CustomTime time.Time
	// CRC32C is the CRC32 checksum of the object, using the Castagnoli93 polynomial.
	CRC32C uint32
}

// CloudStorage defines a generic interface for blob storage operations.
type CloudStorage interface {
	// ReadObject reads the raw contents of an object.
	// It must return ErrNotFound if the object does not exist.
	ReadObject(ctx context.Context, path string) ([]byte, error)

	// ReadObjectAttrs reads the attributes of an object.
	// It must return ErrNotFound if the object does not exist.
	ReadObjectAttrs(ctx context.Context, path string) (*Attrs, error)

	// WriteObject writes a complete byte slice to a storage object.
	WriteObject(ctx context.Context, path string, data []byte, opts *WriteOptions) error

	// Objects returns an iterator over objects that match the prefix.
	Objects(ctx context.Context, prefix string) iter.Seq2[string, error]

	// Close closes the CloudStorage client.
	Close() error
}
