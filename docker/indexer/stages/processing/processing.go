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

	deflog "log"

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
	Store(ctx context.Context, repoInfo *preparation.Result, hashType string, bucketResults [][]*FileResult, treeNodes []*BucketNode) error
}

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

// FileResult holds the per file hash and path information.
type BucketNode struct {
	NodeHash Hash `datastore:"node_hash"`
	// ChildHashes    []Hash `datastore:"child_hashes,noindex"`
	// Height         int    `datastore:"depth,noindex"`
	FilesContained int `datastore:"files_contained,noindex"`
}

// Stage holds the data structures necessary to perform the processing.
type Stage struct {
	Storer                    Storer
	RepoHdl                   *storage.BucketHandle
	Input                     *pubsub.Subscription
	PubSubOutstandingMessages int
}

// bucketCount should be a divisor of 2^16
const bucketCount = 512

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
		log.Infof("begin processing: '%v' @ '%v'", repoInfo.Name, repoInfo.Version)
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
			log.Infof("successfully processed: '%v' @ '%v'", repoInfo.Name, repoInfo.Version)
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

	log.Info("begin processing tree")
	treeResults, bucketResults := processBuckets(fileResults)
	log.Info("begin storage")
	return s.Storer.Store(ctx, repoInfo, shared.MD5, bucketResults, treeResults)
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
			for k := 0; k < len(buckets[bucketIdx][i].Hash); k++ {
				if buckets[bucketIdx][i].Hash[k] < buckets[bucketIdx][j].Hash[k] {
					return true
				}
				if buckets[bucketIdx][i].Hash[k] > buckets[bucketIdx][j].Hash[k] {
					return false
				}
			}
			return false
		})

		hasher := md5.New()
		for _, v := range buckets[bucketIdx] {
			_, err := hasher.Write(v.Hash)
			if err != nil {
				deflog.Panicf("Hasher error: %v", err)
			}
		}

		results[bucketIdx] = &BucketNode{
			NodeHash:       hasher.Sum(nil),
			FilesContained: len(buckets[bucketIdx]),
		}
	}

	return results, buckets
}
