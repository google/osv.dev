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

package models

import (
	"context"
	"time"
)

const (
	// MaxMatchesToCare matches the Python API's _MAX_MATCHES_TO_CARE.
	// If a bucket has too many matches, it is ignored as a useful indicator.
	MaxMatchesToCare = 100
)

// RepoIndex represents a single repository entry in the database.
type RepoIndex struct {
	ID                string
	Name              string
	BaseCPE           string
	Commit            []byte
	Tag               string
	When              time.Time
	RepoType          string
	RepoAddr          string
	FileExts          []string
	FileHashType      string
	EmptyBucketBitmap []byte
	FileCount         int
}

// RepoIndexBucket represents a hashed bucket of files for a specific repository state.
type RepoIndexBucket struct {
	ParentID       string
	NodeHash       []byte
	FilesContained int
}

// RepoIndexStore defines the repository interface for querying repo index data.
type RepoIndexStore interface {
	// QueryBuckets finds all RepoIndexBucket entities matching any of the given node hashes,
	// grouped by the hex-encoded string of the node hash.
	QueryBuckets(ctx context.Context, nodeHashes [][]byte) (map[string][]*RepoIndexBucket, error)

	// GetRepoIndexes fetches the parent RepoIndex entities for the given IDs.
	GetRepoIndexes(ctx context.Context, ids []string) ([]*RepoIndex, error)
}
