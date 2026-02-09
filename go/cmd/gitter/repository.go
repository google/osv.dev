package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
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
	Parents []SHA1
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
	commitDetails map[SHA1]*Commit
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
		commitDetails:    make(map[SHA1]*Commit),
		tagToCommit:      make(map[string]SHA1),
		patchIDToCommits: make(map[SHA1][]SHA1),
	}
}

// LoadRepository loads a repo from disk into memory.
func LoadRepository(ctx context.Context, repoPath string) (*Repository, error) {
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

	// Temp outFile for git log output
	tmpFile, err := os.CreateTemp(r.repoPath, "git-log.out")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Run git log via bash because redirecting to file is faster than using pipe
	_, err = runCmd(ctx, r.repoPath, nil, "bash", "-c", "git log --all --full-history --sparse --topo-order --format="+gitLogFormat+" > "+tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to run git log: %w", err)
	}

	// Read git log output
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to open git-log.out: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 1024*1024)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSuffix(line, "\n")
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
			Hash:    childHash,
			Tags:    tags,
			Parents: parentHashes,
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

		r.commitDetails[childHash] = &commit

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
	defer rPipe.Close()
	// wPipe should be closed in the goroutine where we wait for git show
	// But keeping this defer as a failsafe
	defer wPipe.Close()

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

	// Channel to capture errors from git show
	showErrChan := make(chan error, 1)

	// Write hashes to git show stdin
	go func() {
		defer in.Close()
		for _, hash := range chunk {
			fmt.Fprintf(in, "%s\n", hex.EncodeToString(hash[:]))
		}
	}()

	// Wait for git show to finish
	go func() {
		err := cmdShow.Wait()
		showErrChan <- err
		wPipe.Close() // close pipe to send EOF to git patch-id
	}()

	// Read results from stdout of git patch-id
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

	// Wait for git patch-id to finish
	if err := cmdPatchID.Wait(); err != nil {
		return fmt.Errorf("failed to finish git patch-id: %w", err)
	}

	// Wait for git show to finish
	if err := <-showErrChan; err != nil {
		return fmt.Errorf("failed to finish git show: %w", err)
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

// Affected returns a list of commits that are affected by the given introduced, fixed and last_affected events
func (r *Repository) Affected(introduced, fixed, lastAffected []SHA1, cherrypick bool) []*Commit {
	r.repoMu.Lock()
	defer r.repoMu.Unlock()

	// Expands the introduced and fixed commits to include cherrypick equivalents
	// lastAffected should not be expanded because it does not imply a "fix" commit that can be cherrypicked to other branches
	if cherrypick {
		introduced = r.expandByCherrypick(introduced)
		fixed = r.expandByCherrypick(fixed)
	}

	safeCommits := r.findSafeCommits(introduced, fixed, lastAffected)

	var affectedCommits []*Commit

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

// findSafeCommits returns a set of commits that are non-vulnerable
// Traversing from fixed and children of last affected to the next introduced (if exist)
func (r *Repository) findSafeCommits(introduced, fixed, lastAffected []SHA1) map[SHA1]struct{} {
	introducedMap := make(map[SHA1]struct{})
	for _, commit := range introduced {
		introducedMap[commit] = struct{}{}
	}

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

// expandByCherrypick expands a slice of commits by adding commits that have the same Patch ID (cherrypicked commits) returns a new list containing the original commits PLUS any other commits that share the same Patch ID
func (r *Repository) expandByCherrypick(commits []SHA1) []SHA1 {
	unique := make(map[SHA1]struct{}, len(commits)) // avoid duplication
	var zeroPatchID SHA1

	for _, hash := range commits {
		unique[hash] = struct{}{}

		// Find patch ID from commit details
		details, ok := r.commitDetails[hash]

		if !ok || details.PatchID == zeroPatchID {
			continue
		}

		// Find equivalent commits
		equivalents := r.patchIDToCommits[details.PatchID]
		// TODO: I think this logic will always add the current commit one more time, which isn't a problem because we're using map but still suboptimal
		for _, eq := range equivalents {
			unique[eq] = struct{}{}
		}
	}

	keys := slices.Collect(maps.Keys(unique))
	return keys
}

// Between walks and returns the commits that are strictly between introduced (inclusive) and limit (exclusive)
func (r *Repository) Between(introduced, limit []SHA1) []*Commit {
	r.repoMu.Lock()
	defer r.repoMu.Unlock()

	var affectedCommits []*Commit

	introMap := make(map[SHA1]struct{}, len(introduced))
	for _, commit := range introduced {
		introMap[commit] = struct{}{}
	}

	// DFS to walk from limit(s) to introduced (follow first parent)
	stack := make([]SHA1, len(limit))
	copy(stack, limit)

	visited := make(map[SHA1]struct{})

	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, ok := visited[curr]; ok {
			continue
		}
		// If commit is in introduced, we can stop the traversal
		if _, ok := introMap[curr]; ok {
			continue
		}
		visited[curr] = struct{}{}

		// Otherwise, add to affected commits
		details, ok := r.commitDetails[curr]
		if !ok {
			continue
		}

		affectedCommits = append(affectedCommits, details)

		// Add first parent to stack to only walk the linear branch
		if len(details.Parents) > 0 {
			stack = append(stack, details.Parents[0])
		}
	}

	return affectedCommits
}
