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

package api

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/protobuf/testing/protocmp"

	pb "osv.dev/bindings/go/api"
)

type mockRepoIndexStore struct {
	buckets  map[string][]*models.RepoIndexBucket
	indexes  map[string]*models.RepoIndex
	queryErr error
	getErr   error
}

func (m *mockRepoIndexStore) QueryBuckets(_ context.Context, nodeHashes [][]byte) (map[string][]*models.RepoIndexBucket, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	res := make(map[string][]*models.RepoIndexBucket)
	for _, hash := range nodeHashes {
		hexHash := hex.EncodeToString(hash)
		if buckets, ok := m.buckets[hexHash]; ok {
			res[hexHash] = buckets
		} else {
			res[hexHash] = nil
		}
	}

	return res, nil
}

func (m *mockRepoIndexStore) GetRepoIndexes(_ context.Context, ids []string) ([]*models.RepoIndex, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	var res []*models.RepoIndex
	for _, id := range ids {
		if idx, ok := m.indexes[id]; ok {
			res = append(res, idx)
		} else {
			res = append(res, nil)
		}
	}

	return res, nil
}

func TestDetermineVersion(t *testing.T) {
	ctx := context.Background()

	// Helper to calculate MD5 of a single hash (the bucket hash for single-item buckets)
	hash1 := []byte{0, 1}
	hash2 := []byte{0, 2}
	md5_1 := md5.Sum(hash1) //nolint:gosec
	md5_2 := md5.Sum(hash2) //nolint:gosec

	// Perfect match bitmap: Bucket 1 and Bucket 2 are non-empty
	// (bit 1 and bit 2 of byte 0 are set: 1<<1 | 1<<2 = 2 | 4 = 6)
	perfectBitmap := make([]byte, 64)
	perfectBitmap[0] = 6

	tests := []struct {
		name         string
		query        *pb.VersionQuery
		mockBuckets  map[string][]*models.RepoIndexBucket
		mockIndexes  map[string]*models.RepoIndex
		mockQueryErr error
		mockGetErr   error
		want         *pb.VersionMatchList
		wantErr      bool
	}{
		{
			name:  "Empty Query",
			query: &pb.VersionQuery{},
			want:  &pb.VersionMatchList{Matches: nil},
		},
		{
			name: "Perfect Match",
			query: &pb.VersionQuery{
				Name: "test-lib",
				FileHashes: []*pb.FileHash{
					{FilePath: "file1.txt", Hash: hash1},
					{FilePath: "file2.txt", Hash: hash2},
				},
			},
			mockBuckets: map[string][]*models.RepoIndexBucket{
				hex.EncodeToString(md5_1[:]): {
					{ParentID: "test-repo-v1.0.0", NodeHash: md5_1[:], FilesContained: 1},
				},
				hex.EncodeToString(md5_2[:]): {
					{ParentID: "test-repo-v1.0.0", NodeHash: md5_2[:], FilesContained: 1},
				},
			},
			mockIndexes: map[string]*models.RepoIndex{
				"test-repo-v1.0.0": {
					ID:                "test-repo-v1.0.0",
					Name:              "test-lib",
					RepoAddr:          "https://github.com/test/lib",
					Tag:               "refs/tags/v1.0.0",
					Commit:            []byte{0xde, 0xad, 0xbe, 0xef},
					FileCount:         2,
					EmptyBucketBitmap: perfectBitmap,
				},
			},
			want: &pb.VersionMatchList{
				Matches: []*pb.VersionMatch{
					{
						Score:              1.0,
						MinimumFileMatches: 2,
						EstimatedDiffFiles: 0,
						RepoInfo: &pb.VersionRepositoryInformation{
							Type:    pb.VersionRepositoryInformation_GIT,
							Address: "https://github.com/test/lib",
							Commit:  "deadbeef",
							Tag:     "v1.0.0",
							Version: "1.0.0",
						},
					},
				},
			},
		},
		{
			name: "Partial Match (Missed File)",
			query: &pb.VersionQuery{
				Name: "test-lib",
				FileHashes: []*pb.FileHash{
					{FilePath: "file1.txt", Hash: hash1},
				},
			},
			mockBuckets: map[string][]*models.RepoIndexBucket{
				hex.EncodeToString(md5_1[:]): {
					{ParentID: "test-repo-v1.0.0", NodeHash: md5_1[:], FilesContained: 1},
				},
			},
			mockIndexes: map[string]*models.RepoIndex{
				"test-repo-v1.0.0": {
					ID:                "test-repo-v1.0.0",
					Name:              "test-lib",
					RepoAddr:          "https://github.com/test/lib",
					Tag:               "refs/tags/v1.0.0",
					Commit:            []byte{0xde, 0xad, 0xbe, 0xef},
					FileCount:         2,
					EmptyBucketBitmap: perfectBitmap,
				},
			},
			// The query only has 1 file, but the repo has 2.
			// Bitmap for query: only bucket 1 is non-empty (bitmap = [2, 0, ..., 0]).
			// Missed empty buckets (repo non-empty but query empty): Bucket 2 is empty in query but non-empty in repo (missed = 1).
			// Score will be lower than 1.0.
			want: &pb.VersionMatchList{
				Matches: []*pb.VersionMatch{
					{
						Score:              0.5, // 1 match out of 2 max files
						MinimumFileMatches: 1,
						EstimatedDiffFiles: 1,
						RepoInfo: &pb.VersionRepositoryInformation{
							Type:    pb.VersionRepositoryInformation_GIT,
							Address: "https://github.com/test/lib",
							Commit:  "deadbeef",
							Tag:     "v1.0.0",
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				repoIndexStore: &mockRepoIndexStore{
					buckets:  tt.mockBuckets,
					indexes:  tt.mockIndexes,
					queryErr: tt.mockQueryErr,
					getErr:   tt.mockGetErr,
				},
			}

			got, err := s.DetermineVersion(ctx, &pb.DetermineVersionParameters{Query: tt.query})
			if (err != nil) != tt.wantErr {
				t.Fatalf("DetermineVersion() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("DetermineVersion() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
