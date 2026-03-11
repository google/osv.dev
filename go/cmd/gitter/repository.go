package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
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
	Refs    []string
}

// Repository holds the commit graph and other details for a git repository.
type Repository struct {
	// Protects patchIDToCommits during parallel patch ID calculations
	patchIDMu sync.Mutex
	// Path to the .git directory within gitter's working dir
	repoPath string
	// Adjacency list: Parent -> []Children
	commitGraph map[SHA1][]SHA1
	// Actual commit details
	commitDetails map[SHA1]*Commit
	// Store refs to commit because it's useful for CVE conversion
	refToCommit map[string]SHA1
	// For cherry-pick detection: PatchID -> []commit hash
	patchIDToCommits map[SHA1][]SHA1
	// Root commits (commits with no parents)
	// In a typical repository this is the initial commit
	rootCommits []SHA1
}

// %H commit hash; %P parent hashes; %D:refs (tab delimited)
// We use \x09 (tab) as delimiter because it is disallowed in git refs and won't appear in hashes
const gitLogFormat = "%H%x09%P%x09%D"

// Number of workers for patch ID calculation
var workers = 16

// NewRepository initializes a new Repository struct.
func NewRepository(repoPath string) *Repository {
	return &Repository{
		repoPath:         repoPath,
		commitGraph:      make(map[SHA1][]SHA1),
		commitDetails:    make(map[SHA1]*Commit),
		refToCommit:      make(map[string]SHA1),
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
		logger.InfoContext(ctx, "Loaded repository cache", slog.Int("commits", len(cache.GetCommits())))
	} else {
		if errors.Is(err, os.ErrNotExist) {
			// It's fine if cache doesn't exist, log it just in case
			logger.InfoContext(ctx, "No repository cache found")
		} else {
			return nil, fmt.Errorf("failed to load repository cache: %w", err)
		}
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
		logger.ErrorContext(ctx, "Failed to save repository cache", slog.Any("err", err))
	}

	return repo, nil
}

// buildCommitGraph builds the commit graph and associate commit details from scratch
// Returns a list of new commit hashes that don't have cached Patch IDs.
// The new commit list is in reverse chronological order based on commit date (the default for git log).
func (r *Repository) buildCommitGraph(ctx context.Context, cache *pb.RepositoryCache) ([]SHA1, error) {
	logger.InfoContext(ctx, "Starting graph construction")
	start := time.Now()

	// Build cache map
	cachedPatchIDs := make(map[SHA1]SHA1)
	if cache != nil {
		commits := cache.GetCommits()
		for _, c := range commits {
			h := c.GetHash()
			pid := c.GetPatchId()
			if len(h) == 20 && len(pid) == 20 {
				cachedPatchIDs[SHA1(h)] = SHA1(pid)
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

	// `git log --all --full-history --sparse --format=%H%x09%P%x09%D > git-log.out`
	// --all: all branches
	// --full-history + --sparse: full-history alone still prunes TREESAME commit so we combine that with --sparse to actually get the full history of a repository
	// We are also running via bash because redirecting to file is faster than using stdout pipe and git binary's own --output flag
	err = runCmd(ctx, r.repoPath, nil, "bash", "-c", "git log --all --full-history --sparse --format="+gitLogFormat+" > "+tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to run git log: %w", err)
	}

	// Read git log output
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to open git-log.out: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Handle context cancel within the loop to exit faster if we're processing a very large repo
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Example of a line of git log output
		// 4c9bdbf0e2d45a5297cc080c3ebe809c0cca3581		bc0e4b4c4dbf7932fab7d264929d4d820e82c817 65be82edcdbc5aa6eeea23655cc96b5c84547d3b		upstream/master, upstream/HEAD\n
		// Corresponds to: commit hash \t parent hashes (space delimited) \t refs (comma delimited)
		line := scanner.Text()
		commitInfo := strings.Split(line, "\t")

		var childHash SHA1
		parentHashes := []SHA1{}
		refs := []string{}

		switch len(commitInfo) {
		case 3:
			// refs are separated by commas
			rawRefs := strings.Split(commitInfo[2], ", ")
			for _, ref := range rawRefs {
				if ref == "" {
					continue
				}
				// Remove prefixes from tags, other refs such as branches will be left as is
				if strings.HasPrefix(ref, "tag: ") {
					tag := strings.TrimPrefix(ref, "tag: ")
					refs = append(refs, tag)
				} else {
					// clean up HEAD -> branch-name to just keep the branch name
					ref = strings.TrimPrefix(ref, "HEAD -> ")
					refs = append(refs, ref)
				}
			}

			fallthrough
		case 2:
			// parent hashes are separated by spaces
			parents := strings.Fields(commitInfo[1])
			for _, parent := range parents {
				hash, err := hex.DecodeString(parent)
				if err != nil {
					logger.ErrorContext(ctx, "Failed to decode hash", slog.String("parent", parent), slog.Any("err", err))
					continue
				}
				parentHashes = append(parentHashes, SHA1(hash))
			}

			fallthrough
		case 1:
			hash, err := hex.DecodeString(commitInfo[0])
			if err != nil {
				logger.ErrorContext(ctx, "Failed to decode hash", slog.String("child", commitInfo[0]), slog.Any("err", err))
				continue
			}
			childHash = SHA1(hash)
		default:
			// No line should be completely empty (doesn't even have a commit hash) so error
			logger.ErrorContext(ctx, "Invalid commit info", slog.String("line", line))
			continue
		}

		// We want to keep the root commit (no parent) easily accessible
		if len(parentHashes) == 0 {
			r.rootCommits = append(r.rootCommits, childHash)
		}

		// Add commit to graph (parent -> []child)
		for _, parentHash := range parentHashes {
			r.commitGraph[parentHash] = append(r.commitGraph[parentHash], childHash)
		}

		commit := Commit{
			Hash:    childHash,
			Refs:    refs,
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

		// Also populate the ref-to-commit map
		for _, ref := range refs {
			r.refToCommit[ref] = childHash
		}
	}

	logger.InfoContext(ctx, "Commit graph completed", slog.Int("new_commits", len(newCommits)), slog.Duration("duration", time.Since(start)))

	return newCommits, nil
}

// calculatePatchIDs calculates patch IDs only for the specific commits provided.
// Commits should be passed in order if possible. Processing linear commits sequentially improves performance slightly (in the 'git show' commands).
func (r *Repository) calculatePatchIDs(ctx context.Context, commits []SHA1) error {
	logger.InfoContext(ctx, "Starting patch ID calculation")
	start := time.Now()

	// Number of workers
	if len(commits) < workers {
		workers = len(commits)
	}

	chunkSize := len(commits) / workers

	errg, ctx := errgroup.WithContext(ctx)

	// Splitting the commits into chunks for parallel processing while maintaining commit order
	for i := range workers {
		start := i * chunkSize
		end := start + chunkSize
		// Last worker takes the remainder
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

	logger.InfoContext(ctx, "Patch ID calculation completed", slog.Int("commits", len(commits)), slog.Duration("duration", time.Since(start)))

	return nil
}

// calculatePatchIDsWorker calculates patch IDs and update CommitDetail and patchIDToCommits map.
// Essentially running `git show <flags> <commit hash> | git patch-id --stable`
func (r *Repository) calculatePatchIDsWorker(ctx context.Context, chunk []SHA1) error {
	// Prepare git commands
	// `git show --stdin --patch --first-parent --no-color`:
	// --patch to show diffs in a format that can be directly piped into `git patch-id`
	// --first-parent: when there are multiple parents (e.g. a merge commit), full diff with respect to first parent (usually the main / master branch)
	cmdShow := prepareCmd(ctx, r.repoPath, nil, "git", "show", "--stdin", "--patch", "--first-parent", "--no-color")
	// `git patch-id --stable`:
	// --stable ensures that reordering file diffs does not affect the patch ID
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
			// Handle context cancel
			if ctx.Err() != nil {
				return
			}
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
		// Handle context cancel to exit faster as this can be a long process
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Format of git patch-id result: <patch ID> <commit hash>
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
	r.patchIDMu.Lock()
	defer r.patchIDMu.Unlock()

	commit := r.commitDetails[commitHash]
	commit.PatchID = patchID
	r.commitDetails[commitHash] = commit

	r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], commitHash)
}

// parseHashes converts slice of string hashes input into slice of SHA1
func (r *Repository) parseHashes(ctx context.Context, hashesStr []string, isIntroduced bool) []SHA1 {
	hashes := make([]SHA1, 0, len(hashesStr))
	for _, hash := range hashesStr {
		if isIntroduced && hash == "0" {
			hashes = append(hashes, r.rootCommits...)
			continue
		}

		hashBytes, err := hex.DecodeString(hash)
		// Log error but continue with the rest of the hashes if a commit hash is invalid
		if err != nil {
			logger.ErrorContext(ctx, "failed to decode commit hash", slog.String("hash", hash), slog.Any("err", err))
			continue
		}
		if len(hashBytes) != 20 {
			logger.ErrorContext(ctx, "invalid hash length", slog.String("hash", hash), slog.Int("len", len(hashBytes)))
			continue
		}

		hashes = append(hashes, SHA1(hashBytes))
	}

	return hashes
}

// Affected returns a list of commits that are affected by the given introduced, fixed and last_affected events
func (r *Repository) Affected(ctx context.Context, se *SeparatedEvents, cherrypickIntro, cherrypickFixed bool) []*Commit {
	introduced := r.parseHashes(ctx, se.Introduced, true)
	fixed := r.parseHashes(ctx, se.Fixed, false)
	lastAffected := r.parseHashes(ctx, se.LastAffected, false)

	// Expands the introduced and fixed commits to include cherrypick equivalents
	// lastAffected should not be expanded because it does not imply a "fix" commit that can be cherrypicked to other branches
	if cherrypickIntro {
		introduced = r.expandByCherrypick(introduced)
	}
	if cherrypickFixed {
		fixed = r.expandByCherrypick(fixed)
	}

	// Fixed commits and children of last affected are both in this set
	// For graph traversal sake they are both considered the fix
	fixedMap := make(map[SHA1]struct{}, len(fixed)+len(lastAffected))

	for _, commit := range fixed {
		fixedMap[commit] = struct{}{}
	}

	for _, commit := range lastAffected {
		if _, ok := r.commitGraph[commit]; ok {
			for _, child := range r.commitGraph[commit] {
				fixedMap[child] = struct{}{}
			}
		}
	}

	// The graph traversal
	// affectedMap deduplicates the affected commits from the graph walk from each introduced commit
	affectedMap := make(map[SHA1]struct{})

	// Walk each introduced commit and find its affected commit
	for _, intro := range introduced {
		// BFS from intro
		queue := []SHA1{intro}
		unaffectableMap := make(map[SHA1]struct{})
		affectedFromIntro := make(map[SHA1]struct{})
		visited := make(map[SHA1]struct{})

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			if _, ok := visited[curr]; ok {
				continue
			}
			visited[curr] = struct{}{}

			// Descendant of a fixed commit
			if _, ok := unaffectableMap[curr]; ok {
				continue
			}

			// If we hit a fixed commit, its entire tree is treated as unaffectable
			// as any downstream commit can go through this fixed commit to become unaffected
			if _, ok := fixedMap[curr]; ok {
				unaffectableMap[curr] = struct{}{}
				// Inline DFS from current (fixed) node to make all descendants as unaffected / unaffectable
				// 1. If a previous path added the descendant to affected list, remove it
				// 2. Add to the unaffectable set to block future paths
				stack := []SHA1{curr}
				for len(stack) > 0 {
					unaffected := stack[len(stack)-1]
					stack = stack[:len(stack)-1]

					// Remove from affected list if it was reached via a previous non-fixed path.
					delete(affectedFromIntro, unaffected)

					if children, ok := r.commitGraph[unaffected]; ok {
						for _, child := range children {
							// Continue down the path if the child isn't already blocked.
							if _, ok := unaffectableMap[child]; !ok {
								unaffectableMap[child] = struct{}{}
								stack = append(stack, child)
							}
						}
					}
				}

				continue
			}

			// Otherwise, add to the intro-specific affected list and continue
			affectedFromIntro[curr] = struct{}{}
			if children, ok := r.commitGraph[curr]; ok {
				queue = append(queue, children...)
			}
		}

		// Add the final affected list of this introduced commit to the global set
		for commit := range affectedFromIntro {
			affectedMap[commit] = struct{}{}
		}
	}

	// Return the affected commit details
	affectedCommits := make([]*Commit, 0, len(affectedMap))
	for commit := range affectedMap {
		affectedCommits = append(affectedCommits, r.commitDetails[commit])
	}

	return affectedCommits
}

// expandByCherrypick expands a slice of commits by adding commits that have the same Patch ID (cherrypicked commits) returns a new list containing the original commits + any other commits that share the same Patch ID
func (r *Repository) expandByCherrypick(commits []SHA1) []SHA1 {
	unique := make(map[SHA1]struct{}, len(commits)) // avoid duplication
	var zeroPatchID SHA1

	for _, hash := range commits {
		// Find patch ID from commit details
		details, ok := r.commitDetails[hash]
		if !ok || details.PatchID == zeroPatchID {
			unique[hash] = struct{}{}
			continue
		}

		// Add equivalent commits with the same Patch ID (including the current commit)
		equivalents := r.patchIDToCommits[details.PatchID]
		for _, eq := range equivalents {
			unique[eq] = struct{}{}
		}
	}

	keys := slices.Collect(maps.Keys(unique))

	return keys
}

// Between walks and returns the commits that are strictly between introduced (inclusive) and limit (exclusive)
func (r *Repository) Limit(ctx context.Context, se *SeparatedEvents) []*Commit {
	introduced := r.parseHashes(ctx, se.Introduced, true)
	limit := r.parseHashes(ctx, se.Limit, false)

	var affectedCommits []*Commit

	introMap := make(map[SHA1]struct{}, len(introduced))
	for _, commit := range introduced {
		introMap[commit] = struct{}{}
	}

	// DFS to walk from limit(s) to introduced (follow first parent)
	stack := make([]SHA1, 0, len(limit))
	// Start from limits' parents
	for _, commit := range limit {
		details, ok := r.commitDetails[commit]
		if !ok {
			continue
		}
		if len(details.Parents) > 0 {
			stack = append(stack, details.Parents[0])
		}
	}

	visited := make(map[SHA1]struct{})

	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, ok := visited[curr]; ok {
			continue
		}
		visited[curr] = struct{}{}

		// Add current node to affected commits
		details, ok := r.commitDetails[curr]
		if !ok {
			continue
		}

		affectedCommits = append(affectedCommits, details)

		// If commit is in introduced, we can stop the traversal after adding it to affected
		if _, ok := introMap[curr]; ok {
			continue
		}

		// In git merge, first parent is the HEAD commit at the time of merge (on the branch that gets merged into)
		if len(details.Parents) > 0 {
			stack = append(stack, details.Parents[0])
		}
	}

	return affectedCommits
}
