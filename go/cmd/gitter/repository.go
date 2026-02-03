package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	pb "github.com/google/osv.dev/go/cmd/gitter/pb/repository"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
)

type SHA1 [20]byte

type Commit struct {
	Hash    SHA1
	PatchID SHA1
	Tags    []string
}

// Repository holds the commit graph and other details for a git repository.
type Repository struct {
	repoMu sync.Mutex
	// Path to the .git directory within gitter's working dir
	repoPath string
	// Adjacency list: Parent -> []Children
	commitGraph map[SHA1][]SHA1
	// Actual commit details
	commitDetails map[SHA1]Commit
	// Store tags to commit because it's useful for CVE conversion
	tagToCommit map[string]SHA1
	// For cherry-pick detection: PatchID -> []commit hash
	patchIDToCommits map[SHA1][]SHA1
}

// %H commit hash; %P parent hashes; %D:refs (tab delimited)
const gitLogFormat = "%H%x09%P%x09%D"

// NewRepository initializes a new Repository struct.
func NewRepository(repoPath string) *Repository {
	return &Repository{
		repoPath:         repoPath,
		commitGraph:      make(map[SHA1][]SHA1),
		commitDetails:    make(map[SHA1]Commit),
		tagToCommit:      make(map[string]SHA1),
		patchIDToCommits: make(map[SHA1][]SHA1),
	}
}

// LoadRepository loads a repo from disk into memory.
func LoadRepository(ctx context.Context, repoPath string) (*Repository, error) {
	start := time.Now()

	repo := NewRepository(repoPath)

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
	newCommits, err := repo.buildCommitGraph(ctx, cache)
	if err != nil {
		return nil, fmt.Errorf("failed to build commit graph: %w", err)
	}

	if len(newCommits) > 0 {
		if err := repo.calculatePatchIDs(ctx, newCommits); err != nil {
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

// buildCommitGraph builds the commit graph and associate commit details from scratch
func (r *Repository) buildCommitGraph(ctx context.Context, cache *pb.RepositoryCache) ([]SHA1, error) {
	logger.Info("Starting graph construction", slog.String("repo", r.repoPath))
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

	// Run git log
	cmd := prepareCmd(ctx, r.repoPath, nil, "git", "log", "--all", "--full-history", "--sparse", "--format="+gitLogFormat)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git log: %w", err)
	}
	defer func() {
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			logger.Error("git log command failed", slog.Any("err", err))
		}
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// Example of a line of commit info
		// b1e3d7a8cbfa38bb2b678eff819fc4926b85c494\x09de84b0dd689622922a54d1bc6cc45c384c7ff8bd\x09HEAD -> master, tag: v2025.01.01
		commitInfo := strings.Split(line, "\x09")

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
func (r *Repository) calculatePatchIDs(ctx context.Context, commits []SHA1) error {
	logger.Info("Starting patch ID calculation", slog.String("repo", r.repoPath))
	start := time.Now()

	// Number of workers
	workers := runtime.NumCPU()
	if len(commits) < workers {
		workers = len(commits)
	}

	chunkSize := len(commits) / workers

	errg, ctx := errgroup.WithContext(ctx)

	for i := 0; i < workers; i++ {
		start := i * chunkSize
		end := start + chunkSize

		if i == workers-1 {
			end = len(commits)
		}
		errg.Go(func() error {
			return r.calculatePatchIDsWorker(ctx, commits[start:end])
		})
	}

	if err := errg.Wait(); err != nil {
		return fmt.Errorf("failed to calculate patch IDs: %w", err)
	}

	logger.Info("Patch ID calculation completed", slog.Int("commits", len(commits)), slog.Duration("duration", time.Since(start)))
	return nil
}

func (r *Repository) calculatePatchIDsWorker(ctx context.Context, chunk []SHA1) error {
	// Prepare git commands
	// TODO: Replace with plumbing cmd `git diff-tree`, might be slightly faster
	cmdShow := prepareCmd(ctx, r.repoPath, nil, "git", "show", "--stdin", "--patch", "--first-parent", "--no-color")
	cmdPatchID := prepareCmd(ctx, r.repoPath, nil, "git", "patch-id", "--stable")

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
		for _, hash := range chunk {
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

		r.updatePatchID(hash, patchID)
	}

	return nil
}

func (r *Repository) updatePatchID(commitHash, patchID SHA1) {
	r.repoMu.Lock()
	defer r.repoMu.Unlock()

	commit := r.commitDetails[commitHash]
	commit.PatchID = patchID
	r.commitDetails[commitHash] = commit

	r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], commitHash)
}

func (r *Repository) FindAffectedCommits(introduced, fixed, lastAffected []SHA1) []Commit {
	introducedMap := make(map[SHA1]struct{})
	for _, commit := range introduced {
		introducedMap[commit] = struct{}{}
	}
	safeCommits := r.findSafeCommits(introducedMap, fixed, lastAffected)

	var affectedCommits []Commit

	stack := make([]SHA1, len(introduced))
	copy(stack, introduced)

	visited := make(map[SHA1]struct{})

	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, ok := visited[curr]; ok {
			continue
		}
		visited[curr] = struct{}{}

		// If commit is in safe set, we can stop the traversal
		if _, ok := safeCommits[curr]; ok {
			continue
		}

		// Otherwise, add to affected commits
		affectedCommits = append(affectedCommits, r.commitDetails[curr])

		// Add children to DFS stack
		if children, ok := r.commitGraph[curr]; ok {
			stack = append(stack, children...)
		}

	}
	return affectedCommits
}

func (r *Repository) findSafeCommits(introducedMap map[SHA1]struct{}, fixed, lastAffected []SHA1) map[SHA1]struct{} {
	safeSet := make(map[SHA1]struct{})
	stack := make([]SHA1, 0, len(fixed)+len(lastAffected))
	stack = append(stack, fixed...)

	// All children of last affected commits are root for traversal
	for _, commit := range lastAffected {
		if children, ok := r.commitGraph[commit]; ok {
			for _, child := range children {
				stack = append(stack, child)
			}
		}
	}

	// DFS until we hit an "introduced" commit
	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, ok := safeSet[curr]; ok {
			continue
		}
		safeSet[curr] = struct{}{}

		if children, ok := r.commitGraph[curr]; ok {
			for _, child := range children {
				// vuln re-introduced at a later commit, subsequent commits are no longer safe
				if _, ok := introducedMap[child]; ok {
					continue
				}
				stack = append(stack, child)
			}
		}
	}

	return safeSet
}
