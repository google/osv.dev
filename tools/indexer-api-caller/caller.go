package main

import (
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var (
	repoDir  = flag.String("repo", "", "repo directory")
	repo2Dir = flag.String("repo2", "", "repo directory")
	// tagName = flag.String("tag", "", "tag name to checkout")
)

type Hash = []byte

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

func main() {
	flag.Parse()

	fileRes := [][]*FileResult{}
	// file2Res := [][]*FileResult{}
	// buildGit(*repo2Dir, &file2Res)
	buildGit(*repoDir, &fileRes)

	// log.Println(strings.Join(pretty.Diff(fileRes, file2Res), "\n"))
}

func buildGit(repoDir string, out *[][]*FileResult) error {
	// repo, err := git.PlainOpen(*repoDir)
	// if err != nil {
	// 	return fmt.Errorf("failed to open repo: %v", err)
	// }
	// tree, err := repo.Worktree()
	// if err != nil {
	// 	return fmt.Errorf("failed to get work tree: %v", err)
	// }
	// checkoutOptions = git.CheckoutOptions{
	// 	Force: true,

	// }
	// repoInfo.CheckoutOptions.Force = true
	// if err := tree.Checkout(); err != nil {
	// 	return fmt.Errorf("failed to checkout tree: %v", err)
	// }

	fileExts := []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}
	log.Printf("%v", repoDir)
	var fileResults []*FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		for _, ext := range fileExts {
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

	sort.Slice(fileResults, func(i, j int) bool {
		for k := 0; k < len(fileResults[i].Hash); k++ {
			if fileResults[i].Hash[k] < fileResults[j].Hash[k] {
				return true
			}
			if fileResults[i].Hash[k] > fileResults[j].Hash[k] {
				return false
			}
		}
		return false
	})
	_, fileRes := processTree(fileResults)
	*out = fileRes

	log.Printf("%v", len(fileResults))

	b := strings.Builder{}
	b.WriteString(`{"query": {"name":"protobuf", "file_hashes": [`)

	for i, fr := range fileResults {
		// strings.Join()
		if i == len(fileResults)-1 {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"}", base64.StdEncoding.EncodeToString(fr.Hash))
		} else {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"},", base64.StdEncoding.EncodeToString(fr.Hash))
		}
	}
	b.WriteString("]}}")
	// b.WriteRune('\n')

	cmd := exec.Command("bash")
	cmd.Args = append(cmd.Args, "-c", `grpcurl -plaintext -d @ -protoset api_descriptor.pb 127.0.0.1:8000 osv.v1.OSV/DetermineVersion`)
	// log.Printf("%v", cmd)
	pipe, err := cmd.StdinPipe()
	if err != nil {
		log.Panicln(err)
	}
	os.WriteFile("temp.txt", []byte(b.String()), 0644)
	pipe.Write([]byte(b.String()))
	pipe.Close()
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Panicf("%s: %s", err.Error(), string(output))
	}

	log.Println(string(output))
	// ("bash", []string{"-c", b.String()}, nil)
	// fmt.Print(b.String())
	return nil
	// log.Info("Begin processing tree")
	// treeResults, bucketResults := processTree(fileResults)
	// log.Info("Begin stroage")
}

const chunkSize = 4
const bucketCount = 256

func processTree(fileResults []*FileResult) ([][]*TreeNode, [][]*FileResult) {
	// This height includes the root node (height of 1 is just the root)
	heightOfTree := logWithBase(((chunkSize-1)*bucketCount)+1, chunkSize)
	// Tree, 0 is the leaf layer
	var results = make([][]*TreeNode, heightOfTree)
	buckets := make([][]*FileResult, bucketCount)

	for _, fr := range fileResults {
		buckets[fr.Hash[0]] = append(buckets[fr.Hash[0]], fr)
	}

	// Create base layer
	results[0] = make([]*TreeNode, bucketCount)

	for bucketIdx := range buckets {
		// Sort hashes
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
			// log.Printf("height: %d, len: %d, %v\n", height, len(results[height-1]), results[height-1])

			for _, v := range results[height-1][i : i+chunkSize] {
				// log.Printf("%v\n", v.NodeHash)
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

	return results, buckets
}

func logWithBase(x int, base int) int {
	return int(math.Ceil(math.Log(float64(x)) / math.Log(float64(base))))
}
