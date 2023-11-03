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
// Package processing implements the hashing step for each provide input.
package processing

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv.dev/docker/indexer/shared"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"

	log "github.com/golang/glog"
)

type Hash = []byte

// Storer is used to permanently store the results.
type Storer interface {
	Store(ctx context.Context, repoInfo *preparation.Result, hashType string, bucketNodes []*BucketNode) error
	Clean(ctx context.Context, repoInfo *preparation.Result, hashType string) error
}

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

// FileResult holds the per file hash and path information.
type BucketNode struct {
	NodeHash        Hash `datastore:"node_hash"`
	FilesContained  int  `datastore:"files_contained,noindex"`
	DocumentVersion int
}

// Stage holds the data structures necessary to perform the processing.
type Stage struct {
	Storer                    Storer
	RepoHdl                   *storage.BucketHandle
	Input                     *pubsub.Subscription
	PubSubOutstandingMessages int
}

// bucketCount should be a divisor of 2^16
// Changing this will require deleting all RepoIndex entries to
// completely rebuild all entries
const bucketCount = 512

var (
	vendoredLibNames = map[string]struct{}{
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
)

// Run runs the stages and hashes all files for each incoming request.
func (s *Stage) Run(ctx context.Context) error {
	s.Input.ReceiveSettings.MaxOutstandingMessages = s.PubSubOutstandingMessages
	return s.Input.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		// Always ack the message. Transient errors can be solved by the
		// next scheduled run.
		defer m.Ack()
		repoInfo := &preparation.Result{}
		if err := json.Unmarshal(m.Data, repoInfo); err != nil {
			log.Errorf("failed to unmarshal input: %v", err)
			return
		}
		log.Infof("begin processing: '%v' @ '%v'", repoInfo.Name, repoInfo.CommitTag)
		var err error
		switch repoInfo.Type {
		case shared.Git:
			err = s.processGit(ctx, repoInfo)
		default:
			err = errors.New("unknown repository type")
		}
		if err != nil {
			log.Errorf("failed to process input: %v", err)
		} else {
			log.Infof("successfully processed: '%v' @ '%v'", repoInfo.Name, repoInfo.CommitTag)
		}
	})
}

func (s *Stage) processGit(ctx context.Context, repoInfo *preparation.Result) error {
	repoDir, err := shared.CopyFromBucket(ctx, s.RepoHdl, repoInfo.Name)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(repoDir); err != nil {
			log.Errorf("failed to remove repo folder: %v", err)
		}
	}()

	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("failed to open repo: %v", err)
	}
	tree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get work tree: %v", err)
	}
	repoInfo.CheckoutOptions.Force = true
	if err := tree.Checkout(repoInfo.CheckoutOptions); err != nil {
		return fmt.Errorf("failed to checkout tree: %v", err)
	}

	var fileResults []*FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			if _, ok := vendoredLibNames[strings.ToLower(info.Name())]; ok {
				// Ignore vendored libraries, as they can cause bad matches.
				return filepath.SkipDir
			}

			return nil
		}

		for _, ext := range repoInfo.FileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf)
				fileResults = append(fileResults, &FileResult{
					Path: strings.ReplaceAll(p, repoDir, ""),
					Hash: hash[:],
				})
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed during file walk: %v", err)
	}

	log.Info("begin processing buckets")
	bucketResults, _ := processBuckets(fileResults)
	// Build up a bitmap of filled in buckets
	repoInfo.FileCount = len(fileResults)
	repoInfo.EmptyBucketBitmap = createFilledBucketBitmap(bucketResults)
	log.Info("begin storage")
	err = s.Storer.Store(ctx, repoInfo, shared.MD5, bucketResults)
	if err != nil {
		return err
	}

	log.Info("begin cleaning old versions")
	return s.Storer.Clean(ctx, repoInfo, shared.MD5)
}

func createFilledBucketBitmap(nodes []*BucketNode) []byte {
	var bitmap = make([]byte, bucketCount/8)
	for i, v := range nodes {
		var val byte
		if v.FilesContained == 0 {
			val = 0
		} else {
			val = 1
		}
		bitmap[i/8] |= val << (i % 8)
	}
	return bitmap
}

// Returns bucket hashes and the individual file hashes of each bucket
func processBuckets(fileResults []*FileResult) ([]*BucketNode, [][]*FileResult) {
	buckets := make([][]*FileResult, bucketCount)

	for _, fr := range fileResults {
		// Evenly divide into bucketCount buckets,
		idx := binary.BigEndian.Uint16(fr.Hash[0:2]) % bucketCount
		buckets[idx] = append(buckets[idx], fr)
	}

	results := make([]*BucketNode, bucketCount)

	for bucketIdx := range buckets {
		// Sort hashes to produce deterministic bucket hashes
		sort.Slice(buckets[bucketIdx], func(i, j int) bool {
			return bytes.Compare(buckets[bucketIdx][i].Hash, buckets[bucketIdx][j].Hash) < 0
		})

		hasher := md5.New()
		for _, v := range buckets[bucketIdx] {
			// md5.Write can never return a non nil error
			_, _ = hasher.Write(v.Hash)
		}

		results[bucketIdx] = &BucketNode{
			NodeHash:        hasher.Sum(nil),
			FilesContained:  len(buckets[bucketIdx]),
			DocumentVersion: shared.LatestDocumentVersion,
		}
	}

	return results, buckets
}
