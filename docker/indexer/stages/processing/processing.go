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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv.dev/docker/indexer/shared"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
)

type Hash = []byte

// Storer is used to permanently store the results.
type Storer interface {
	Store(ctx context.Context, repoInfo *preparation.Result, hashType string, fileResults []*FileResult, treeNodes [][]*TreeNode) error
}

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

// FileResult holds the per file hash and path information.
type TreeNode struct {
	NodeHash       Hash   `datastore:"node_hash"`
	ChildHashes    []Hash `datastore:"child_hashes,noindex"`
	Height         int    `datastore:"depth,noindex"`
	FilesContained int    `datastore:"files_contained,noindex"`
}

// Stage holds the data structures necessary to perform the processing.
type Stage struct {
	Storer                    Storer
	RepoHdl                   *storage.BucketHandle
	Input                     *pubsub.Subscription
	PubSubOutstandingMessages int
}

// Run runs the stages and hashes all files for each incoming request.
func (s *Stage) Run(ctx context.Context) error {
	s.Input.ReceiveSettings.MaxOutstandingMessages = s.PubSubOutstandingMessages
	return s.Input.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		// Always ack the message. Transient errors can be solved by the
		// next scheduled run.
		defer m.Ack()
		repoInfo := &preparation.Result{}
		if err := json.Unmarshal(m.Data, repoInfo); err != nil {
			log.Fatalf("failed to unmarshal input: %v", err)
			return
		}
		var err error
		switch repoInfo.Type {
		case shared.Git:
			err = s.processGit(ctx, repoInfo)
		default:
			err = errors.New("unknown repository type")
		}
		if err != nil {
			log.Fatalf("failed to process input: %v", err)
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
			log.Fatalf("failed to remove repo folder: %v", err)
		}
	}()
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("failed to open repo: %v", err)
	}
	tree, err := repo.Worktree()
	if err != nil {
		return err
	}
	repoInfo.CheckoutOptions.Force = true
	if err := tree.Checkout(repoInfo.CheckoutOptions); err != nil {
		return err
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
		return err
	}

	treeResults := processTree(fileResults)
	return s.Storer.Store(ctx, repoInfo, shared.MD5, fileResults, treeResults)
}

const chunkSize = 4
const bucketCount = 256

func processTree(fileResults []*FileResult) [][]*TreeNode {
	// This height includes the root node (height of 1 is just the root)
	heightOfTree := logWithBase(((chunkSize-1)*bucketCount)+1, chunkSize)
	// Tree, 0 is the leaf layer
	var results = make([][]*TreeNode, heightOfTree)
	buckets := make([][]Hash, bucketCount)

	for _, fr := range fileResults {
		buckets[fr.Hash[0]] = append(buckets[fr.Hash[0]], fr.Hash)
	}

	// Create base layer
	results[0] = make([]*TreeNode, bucketCount)

	for bucketIdx := range buckets {
		// Sort hashes
		sort.Slice(buckets[bucketIdx], func(i, j int) bool {
			for k := 0; k < len(buckets[bucketIdx][i]); k++ {
				if buckets[bucketIdx][i][k] < buckets[bucketIdx][j][k] {
					return true
				}
				if buckets[bucketIdx][i][k] > buckets[bucketIdx][j][k] {
					return false
				}
			}
			return false
		})

		hasher := md5.New()
		for _, v := range buckets[bucketIdx] {
			_, err := hasher.Write(v)
			if err != nil {
				log.Panicf("Hasher error: %v", err)
			}
		}

		results[0][bucketIdx] = &TreeNode{
			NodeHash:       hasher.Sum(nil),
			ChildHashes:    nil,
			Height:         0,
			FilesContained: len(buckets[bucketIdx]),
		}
	}

	// Start building the higher layers
	for height := 1; height < len(results); height++ {
		results[height] = make([]*TreeNode, len(results[height-1])/chunkSize)
		for i := 0; i < len(results[height-1]); i += chunkSize {
			hasher := md5.New()
			childHashes := []Hash{}
			filesContained := 0
			log.Printf("height: %d, len: %d, %v\n", height, len(results[height-1]), results[height-1])

			for _, v := range results[height-1][i : i+chunkSize] {
				log.Printf("%v\n", v.NodeHash)
				_, err := hasher.Write(v.NodeHash)
				childHashes = append(childHashes, v.NodeHash)
				filesContained += v.FilesContained
				if err != nil {
					log.Panicf("Hasher error: %v", err)
				}
			}
			parentIdx := i / chunkSize
			results[height][parentIdx] = &TreeNode{
				NodeHash:       hasher.Sum(nil),
				ChildHashes:    childHashes,
				Height:         height,
				FilesContained: filesContained,
			}
		}
	}

	return results
}

func logWithBase(x int, base int) int {
	return int(math.Ceil(math.Log(float64(x)) / math.Log(float64(base))))
}
