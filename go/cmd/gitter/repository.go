package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	pb "github.com/google/osv.dev/go/cmd/gitter/pb/repository"
	"github.com/google/osv.dev/go/logger"
)

type SHA1 [20]byte

type Commit struct {
	Hash    SHA1
	PatchID SHA1
	Tags    []string
}

// Repository holds the commit graph and other details for a git repository.
type Repository struct {
	// Adjacency list: Parent -> []Children
	commitGraph map[SHA1][]SHA1
	// Actual commit details
	commitDetails map[SHA1]Commit
	// Store tags to commit because it's useful for CVE conversion
	tagToCommit map[string]SHA1
	// For cherry-pick detection: PatchID -> []commit hash
	patchIDToCommits map[SHA1][]SHA1
}

// %H commit hash; %P parent hashes; %D:refs
const gitLogFormat = "%H;%P;%D" // TODO: Double check if semi-colon is the best delimitor

// NewRepository initializes a new Repository struct.
func NewRepository() *Repository {
	return &Repository{
		commitGraph:      make(map[SHA1][]SHA1),
		commitDetails:    make(map[SHA1]Commit),
		tagToCommit:      make(map[string]SHA1),
		patchIDToCommits: make(map[SHA1][]SHA1),
	}
}

// LoadRepository loads a repo from disk into memory.
// Takes in repo .git file path.
func LoadRepository(ctx context.Context, repoPath string) (*Repository, error) {
	logger.Info("Starting repository loading", slog.String("repo", repoPath))
	start := time.Now()

	repo := NewRepository()

	cachePath := repoPath + ".pb"
	var cache *pb.RepositoryCache

	// Load cache pb file of the repo if exist
	if c, err := loadRepositoryCache(cachePath); err == nil {
		cache = c
		logger.Info("Loaded repository cache", slog.Int("commits", len(cache.Commits)))
	} else {
		// It's fine if cache doesn't exist
		logger.Info("No repository cache found or failed to load", slog.Any("err", err))
	}

	// Commit graph is built from scratch every time
	newCommits, err := repo.buildCommitGraph(ctx, repoPath, cache)
	if err != nil {
		return nil, fmt.Errorf("failed to build commit graph: %w", err)
	}

	if len(newCommits) > 0 {
		if err := repo.calculatePatchIDs(ctx, repoPath, newCommits); err != nil {
			return nil, fmt.Errorf("failed to calculate patch id for commits: %w", err)
		}
	}

	// Save cache
	if err := saveRepositoryCache(cachePath, repo); err != nil {
		logger.Error("Failed to save repository cache", slog.Any("err", err))
	}

	logger.Info("Repository fully processed", slog.Duration("duration", time.Since(start)))
	return repo, nil
}

// Graph is computed from scratch everytime
func (r *Repository) buildCommitGraph(ctx context.Context, repoPath string, cache *pb.RepositoryCache) ([]SHA1, error) {
	logger.Info("Starting graph construction", slog.String("repo", repoPath))
	start := time.Now()

	// Build cache map
	cachedPatchIDs := make(map[SHA1]SHA1)
	if cache != nil {
		for _, c := range cache.Commits {
			if len(c.Hash) == 20 && len(c.PatchId) == 20 {
				cachedPatchIDs[SHA1(c.Hash)] = SHA1(c.PatchId)
			}
		}
	}
	var newCommits []SHA1

	// Temp file for git log
	tmpFile, err := os.CreateTemp("", "git-log-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Run git log
	if _, err := runCmd(ctx, repoPath, nil, "git", "log", "--all", "--date-order", "--format="+gitLogFormat, "--output="+tmpFile.Name()); err != nil {
		return nil, fmt.Errorf("failed to run git log: %w", err)
	}

	file, err := os.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to open temp file: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		// Example of a line of commit info
		// b1e3d7a8cbfa38bb2b678eff819fc4926b85c494;de84b0dd689622922a54d1bc6cc45c384c7ff8bd;HEAD -> master, tag: v2025.01.01
		commitInfo := strings.Split(line, ";")

		childHash := SHA1{}
		parentHashes := []SHA1{}
		tags := []string{}

		switch len(commitInfo) {
		case 3:
			// refs are separated by commas
			refs := strings.Split(commitInfo[2], ", ")
			for _, ref := range refs {
				// Remove prefixes from tags, other refs such as HEAD will be left as is
				if strings.Contains(ref, "tag: ") {
					tags = append(tags, strings.TrimPrefix(ref, "tag: "))
				}
			}
			fallthrough
		case 2:
			// parent hashes are separated by spaces
			parents := strings.Fields(commitInfo[1])
			for _, parent := range parents {
				hash, err := hex.DecodeString(parent)
				if err != nil {
					logger.Error("Failed to decode hash", slog.String("parent", parent), slog.Any("err", err))
					continue
				}
				parentHashes = append(parentHashes, SHA1(hash))
			}
			fallthrough
		case 1:
			hash, err := hex.DecodeString(commitInfo[0])
			if err != nil {
				logger.Error("Failed to decode hash", slog.String("child", commitInfo[0]), slog.Any("err", err))
				continue
			}
			childHash = SHA1(hash)
		default:
			// No line should be completely empty (doesn't even have a commit hash) so error
			logger.Error("Invalid commit info", slog.String("line", line))
			continue
		}

		// Add commit to graph (parent -> []child)
		for _, parentHash := range parentHashes {
			r.commitGraph[parentHash] = append(r.commitGraph[parentHash], childHash)
		}

		commit := Commit{
			Hash: childHash,
			Tags: tags,
		}

		if patchID, ok := cachedPatchIDs[childHash]; ok {
			// Assign saved patch ID to commit details and map if found
			commit.PatchID = patchID
			// Also populate patchIDToCommits map
			r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], childHash)
		} else {
			// Add to slice for patch ID to be generated later
			newCommits = append(newCommits, childHash)
		}

		r.commitDetails[childHash] = commit

		// Also populate the tag-to-commit map
		for _, tag := range tags {
			r.tagToCommit[tag] = childHash
		}
	}

	logger.Info("Commit graph completed", slog.Int("commits", len(r.commitDetails)), slog.Int("nodes", len(r.commitGraph)), slog.Int("new_commits", len(newCommits)), slog.Duration("duration", time.Since(start)))

	return newCommits, nil
}

// calculatePatchIDs calculates patch IDs only for the specific commits provided.
// TODO: Parallelize this
func (r *Repository) calculatePatchIDs(ctx context.Context, repoPath string, commits []SHA1) error {
	logger.Info("Starting patch ID calculation", slog.String("repo", repoPath))
	start := time.Now()

	// Prepare git commands
	// TODO: Replace with plumbing cmd `git diff-tree` might be slightly faster
	cmdShow := exec.CommandContext(ctx, "git", "show", "--stdin", "--patch", "--first-parent", "--no-color")
	cmdShow.Dir = repoPath

	cmdPatchID := exec.CommandContext(ctx, "git", "patch-id", "--stable")
	cmdPatchID.Dir = repoPath

	// Pipe the git show with git patch-id
	in, err := cmdShow.StdinPipe()
	if err != nil {
		return fmt.Errorf("git show stdin pipe error: %w", err)
	}

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("inter-process pipe error: %w", err)
	}
	cmdShow.Stdout = wPipe
	cmdPatchID.Stdin = rPipe

	out, err := cmdPatchID.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git patch-id stdout pipe error: %w", err)
	}

	// Start the processes
	if err := cmdShow.Start(); err != nil {
		return fmt.Errorf("failed to start git show: %w", err)
	}
	if err := cmdPatchID.Start(); err != nil {
		return fmt.Errorf("failed to start git patch-id: %w", err)
	}

	// Write hashes to stdin
	go func() {
		defer in.Close()
		for _, hash := range commits {
			fmt.Fprintf(in, "%s\n", hex.EncodeToString(hash[:]))
		}
	}()

	go func() {
		cmdShow.Wait()
		wPipe.Close()
	}()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()

		// The whole output of git patch-id will be empty if there is no diff (e.g. empty commit), it is safe to just continue
		if line == "" {
			continue
		}

		patchInfo := strings.Fields(line)
		// --first-parent flag in git show should have prevented git patch-id from returning multiple lines of patch IDs
		// return error if this still happens
		if len(patchInfo) != 2 {
			return fmt.Errorf("invalid patch ID format: %s", line)
		}

		patchIDBytes, err := hex.DecodeString(patchInfo[0])
		if err != nil {
			return fmt.Errorf("failed to decode patch ID: %w", err)
		}
		patchID := SHA1(patchIDBytes)

		hashBytes, err := hex.DecodeString(patchInfo[1])
		if err != nil {
			return fmt.Errorf("failed to decode commit hash: %w", err)
		}
		hash := SHA1(hashBytes)

		commit := r.commitDetails[hash]
		commit.PatchID = patchID
		r.commitDetails[hash] = commit

		r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], hash)
	}

	logger.Info("Patch ID calculation completed", slog.Int("count", len(r.commitDetails)), slog.Duration("duration", time.Since(start)))

	return nil
}

func (r *Repository) EnumerateCommits(introduced []SHA1, fixed []SHA1, lastAffected []SHA1) []Commit {
	stack := introduced
	visited := make(map[SHA1]bool)
	fixedMap := map[SHA1]struct{}{}
	for _, commit := range fixed {
		fixedMap[commit] = struct{}{}
	}
	lastAffectedMap := map[SHA1]struct{}{}
	for _, commit := range lastAffected {
		lastAffectedMap[commit] = struct{}{}
	}

	var commits []Commit

	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[curr] {
			continue
		}
		visited[curr] = true

		// Is a fixed commit, we can stop here
		if _, ok := fixedMap[curr]; ok {
			continue
		}

		commits = append(commits, r.commitDetails[curr])

		// Is a last affected commit, still add this commit to result,
		// but no need to add children to stack
		if _, ok := lastAffectedMap[curr]; ok {
			continue
		}

		children := r.commitGraph[curr]
		stack = append(stack, children...)
	}

	return commits
}
