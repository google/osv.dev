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
	"bytes"
	"cmp"
	"context"

	"crypto/md5" //nolint:gosec // indexer uses md5 to hash files
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "osv.dev/bindings/go/api"
)

const (
	bucketSize                     = 512
	minScoreCutoff                 = 0.05
	maxDetermineVerResultsToReturn = 10
	// maxCandidatesToFetch is the number of candidate RepoIndexes we fetch and score.
	// Python limited this to 10, which caused it to arbitrarily discard good matches in
	// tie cases (e.g. many repos with 1 match). We use 100 to resolve these ties and
	// ensure accuracy while keeping Datastore read costs low.
	maxCandidatesToFetch = 100
	tagPrefix            = "refs/tags/"
)

var vendoredLibNames = map[string]struct{}{
	"3rdparty":    {},
	"dep":         {},
	"deps":        {},
	"thirdparty":  {},
	"third-party": {},
	"third_party": {},
	"libs":        {},
	"external":    {},
	"externals":   {},
	"vendor":      {},
	"vendored":    {},
}

func shouldSkipBucket(path string) bool {
	if path == "" {
		return false
	}
	components := strings.Split(path, "/")
	for _, c := range components {
		if _, ok := vendoredLibNames[strings.ToLower(c)]; ok {
			return true
		}
	}

	return false
}

// processBuckets creates buckets in the same process as the indexer.
func processBuckets(fileHashes []*pb.FileHash) ([]*models.RepoIndexBucket, error) {
	buckets := make([][][]byte, bucketSize)

	for _, fh := range fileHashes {
		if len(fh.GetHash()) < 2 {
			continue
		}
		if shouldSkipBucket(fh.GetFilePath()) {
			continue
		}

		idx := binary.BigEndian.Uint16(fh.GetHash()[0:2]) % bucketSize
		buckets[idx] = append(buckets[idx], fh.GetHash())
	}

	results := make([]*models.RepoIndexBucket, bucketSize)
	for i := range bucketSize {
		bucket := buckets[i]
		// Sort hashes lexicographically to produce deterministic bucket hashes
		slices.SortFunc(bucket, bytes.Compare)

		hasher := md5.New() //nolint:gosec
		for _, h := range bucket {
			_, err := hasher.Write(h)
			if err != nil {
				return nil, fmt.Errorf("failed to write hash to hasher: %w", err)
			}
		}

		results[i] = &models.RepoIndexBucket{
			NodeHash:       hasher.Sum(nil),
			FilesContained: len(bucket),
		}
	}

	return results, nil
}

func estimateDiff(numBucketChange int, fileCountDiff int) int {
	// Guard against potential out-of-bound values to prevent Log(<=0) or NaN
	if numBucketChange < 0 {
		numBucketChange = 0
	}
	if numBucketChange >= bucketSize {
		numBucketChange = bucketSize - 1
	}
	estimate := float64(bucketSize) * math.Log(float64(bucketSize+1)/float64(bucketSize-numBucketChange+1))

	// Use RoundToEven to match Python's round() behavior for 0.5,
	// ensuring identical score calculations and preventing filtering discrepancies.
	return fileCountDiff + int(math.RoundToEven(math.Max(estimate-float64(fileCountDiff), 0)/2))
}

var candidateRegex = regexp.MustCompile(`(?i:\d+|rc\d*|alpha\d*|beta\d*|preview\d*)`)
var isWordChar = regexp.MustCompile(`(?i)^[a-z]$`)

func normalizeTag(v string) string {
	if strings.HasPrefix(v, ".") {
		v = "0" + v
	}
	matches := candidateRegex.FindAllStringIndex(v, -1)
	if len(matches) == 0 {
		return v
	}
	components := make([]string, 0, len(matches))
	for _, loc := range matches {
		start, end := loc[0], loc[1]
		matchStr := v[start:end]

		firstChar := strings.ToLower(matchStr[:1])
		if firstChar >= "a" && firstChar <= "z" {
			if start > 0 {
				prevChar := v[start-1 : start]
				if isWordChar.MatchString(prevChar) {
					continue
				}
			}
		}
		components = append(components, matchStr)
	}
	if len(components) == 0 {
		return v
	}

	return strings.Join(components, "-")
}

func (s *server) DetermineVersion(ctx context.Context, req *pb.DetermineVersionParameters) (*pb.VersionMatchList, error) {
	query := req.GetQuery()
	if query == nil {
		return &pb.VersionMatchList{}, nil
	}

	logger.InfoContext(ctx, "DetermineVersion called", "hashes_count", len(query.GetFileHashes()))

	// Filter and prepare file hashes
	var validHashes []*pb.FileHash
	for _, fh := range query.GetFileHashes() {
		if fh.GetHash() != nil && len(fh.GetHash()) <= 100 {
			validHashes = append(validHashes, fh)
		}
	}

	buckets, err := processBuckets(validHashes)
	if err != nil {
		logger.ErrorContext(ctx, "failed to process buckets", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "failed to process buckets")
	}

	nodeHashes := make([][]byte, 0, len(buckets))
	nonEmtpyBucketIndices := make([]int, 0, len(buckets))
	var emptyBucketBitmap [bucketSize / 8]byte // 64 bytes for 512 bits

	for i, b := range buckets {
		if b.FilesContained == 0 {
			continue
		}
		nodeHashes = append(nodeHashes, b.NodeHash)
		nonEmtpyBucketIndices = append(nonEmtpyBucketIndices, i)

		// Set bit in emptyBucketBitmap (little-endian byte order bit allocation)
		emptyBucketBitmap[i/8] |= 1 << (i % 8)
	}

	// Query Datastore via repository
	matchedBucketsByHash, err := s.repoIndexStore.QueryBuckets(ctx, nodeHashes)
	if err != nil {
		if !logger.IsContextError(err) {
			logger.ErrorContext(ctx, "Failed to query RepoIndexBuckets", "error", err)
		}

		return nil, status.Error(codes.Internal, "failed to query repo index buckets")
	}

	fileMatchCount := make(map[string]int)
	bucketMatchCount := make(map[string]int)
	numSkippedBuckets := 0
	skippedFiles := 0

	// We need to keep track of which parent IDs we've seen
	parentIDsSet := make(map[string]struct{})

	for _, idx := range nonEmtpyBucketIndices {
		b := buckets[idx]
		hexHash := hex.EncodeToString(b.NodeHash)
		matches := matchedBucketsByHash[hexHash]

		if len(matches) == models.MaxMatchesToCare {
			numSkippedBuckets++
			skippedFiles += b.FilesContained

			continue
		}

		for _, match := range matches {
			if match.ParentID == "" {
				continue
			}
			parentIDsSet[match.ParentID] = struct{}{}
			fileMatchCount[match.ParentID] += match.FilesContained
			bucketMatchCount[match.ParentID]++
		}
	}

	// Add skipped files back to the match count of all seen parent IDs
	for parentID := range parentIDsSet {
		fileMatchCount[parentID] += skippedFiles
	}

	// Sort parent IDs by bucket match count descending, and limit to maxDetermineVerResultsToReturn
	parentIDs := make([]string, 0, len(parentIDsSet))
	for id := range parentIDsSet {
		parentIDs = append(parentIDs, id)
	}
	slices.SortFunc(parentIDs, func(a, b string) int {
		return -cmp.Compare(bucketMatchCount[a], bucketMatchCount[b])
	})

	if len(parentIDs) > maxCandidatesToFetch {
		parentIDs = parentIDs[:maxCandidatesToFetch]
	}

	repoIndexes, err := s.repoIndexStore.GetRepoIndexes(ctx, parentIDs)
	if err != nil {
		if !logger.IsContextError(err) {
			logger.ErrorContext(ctx, "Failed to get RepoIndexes", "error", err)
		}

		return nil, status.Error(codes.Internal, "failed to get repo indexes")
	}

	matches := make([]*pb.VersionMatch, 0, len(repoIndexes))
	queryFileCount := len(query.GetFileHashes())

	// Inverted empty bucket bitmap of the query
	// (bitwise NOT on the query bitmap, meaning 1 represents empty in query)
	var invertedEmptyBucketBitmap [bucketSize / 8]byte
	for i := range emptyBucketBitmap {
		invertedEmptyBucketBitmap[i] = ^emptyBucketBitmap[i]
	}

	for _, idx := range repoIndexes {
		if idx == nil || len(idx.EmptyBucketBitmap) < bucketSize/8 {
			continue
		}

		// Calculate missed empty buckets
		// We are looking to find cases where the bitmap generated by the user query
		// gives a 0 (meaning empty in query, so 1 in invertedEmptyBucketBitmap),
		// but the bitmap of the repo is a 1 (meaning non-empty in repo).
		missedEmptyBuckets := 0
		for i := range bucketSize / 8 {
			// bitwise AND of inverted query bitmap and repo bitmap
			missed := invertedEmptyBucketBitmap[i] & idx.EmptyBucketBitmap[i]
			missedEmptyBuckets += bits.OnesCount8(missed)
		}

		// Count empty buckets in user query
		emptyBucketCount := 0
		for i := range bucketSize / 8 {
			emptyBucketCount += bits.OnesCount8(invertedEmptyBucketBitmap[i])
		}

		numBucketChange := bucketSize - bucketMatchCount[idx.ID] - emptyBucketCount + missedEmptyBuckets - numSkippedBuckets
		fileCountDiff := int(math.Abs(float64(idx.FileCount - queryFileCount)))

		estimatedDiffFiles := estimateDiff(numBucketChange, fileCountDiff)
		maxFiles := int(math.Max(float64(idx.FileCount), float64(queryFileCount)))
		if maxFiles == 0 {
			continue
		}

		score := float64(maxFiles-estimatedDiffFiles) / float64(maxFiles)
		if score < minScoreCutoff {
			continue
		}

		version := normalizeTag(strings.TrimPrefix(idx.Tag, tagPrefix))
		version = strings.ReplaceAll(version, "-", ".")

		if version == "" {
			continue
		}

		matches = append(matches, &pb.VersionMatch{
			Score:              score,
			MinimumFileMatches: int64(fileMatchCount[idx.ID]),
			EstimatedDiffFiles: int64(estimatedDiffFiles),
			RepoInfo: &pb.VersionRepositoryInformation{
				Type:    pb.VersionRepositoryInformation_GIT,
				Address: idx.RepoAddr,
				Commit:  hex.EncodeToString(idx.Commit),
				Tag:     strings.TrimPrefix(idx.Tag, tagPrefix),
				Version: version,
			},
		})
	}

	// Sort matches descending by score
	slices.SortFunc(matches, func(a, b *pb.VersionMatch) int {
		return -cmp.Compare(a.GetScore(), b.GetScore())
	})

	// Limit results
	if len(matches) > maxDetermineVerResultsToReturn {
		matches = matches[:maxDetermineVerResultsToReturn]
	}

	return &pb.VersionMatchList{Matches: matches}, nil
}
