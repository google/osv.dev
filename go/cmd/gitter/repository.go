package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
)

type SHA1 [20]byte

type Commit struct {
	Hash    SHA1
	PatchID SHA1
	Parents []int
	Tags    []string
}

// Repository holds the commit graph and other details for a git repository.
type Repository struct {
	// Protects patchIDToCommits during parallel patch ID calculations
	patchIDMu sync.Mutex
	// Remote URL for this repository
	URL string
	// Path to the .git directory within gitter's working dir
	repoPath string
	// All commits in the repository (the array index is used as the commit index below)
	commits []*Commit
	// Adjacency list: Parent index -> []Children indexes
	commitGraph [][]int
	// Map of commit hash to its index in the commits slice
	hashToIndex map[SHA1]int
	// Store tags to commit index
	tagToCommit map[string]int
	// For cherry-pick detection: PatchID -> []commit indexes
	patchIDToCommits map[SHA1][]int
	// Root commits (commits with no parents)
	// In a typical repository this is the initial commit
	rootCommits []int
}

// %H commit hash; %P parent hashes; %D:refs (tab delimited)
// We use \x09 (tab) as delimiter because it is disallowed in git refs and won't appear in hashes
const gitLogFormat = "%H%x09%P%x09%D"

// Number of workers for patch ID calculation
var workers = 16

// NewRepository initializes a new Repository struct from a URL.
// If the repository is cloned locally, repoPath is set. Otherwise it remains empty.
func NewRepository(url string) *Repository {
	r := &Repository{
		URL:              url,
		hashToIndex:      make(map[SHA1]int),
		tagToCommit:      make(map[string]int),
		patchIDToCommits: make(map[SHA1][]int),
	}

	repoDirName := getRepoDirName(url)
	path := filepath.Join(gitStorePath, repoDirName)

	// Only if the repo is cloned locally, set repoPath
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		r.repoPath = path
	}

	return r
}

// LoadRepository loads a repo from disk into memory.
func LoadRepository(ctx context.Context, repoPath string) (*Repository, error) {
	repo := &Repository{
		repoPath:         repoPath,
		hashToIndex:      make(map[SHA1]int),
		tagToCommit:      make(map[string]int),
		patchIDToCommits: make(map[SHA1][]int),
	}

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

	var patchIDErr error
	if len(newCommits) > 0 {
		patchIDErr = repo.calculatePatchIDs(ctx, newCommits)
	}

	// If error is anything other than context cancel, exit early without saving
	if patchIDErr != nil && !errors.Is(ctx.Err(), context.Canceled) {
		return nil, fmt.Errorf("failed to calculate patch id for commits: %w", patchIDErr)
	}

	// Save cache
	patchIDCount, err := saveRepositoryCache(cachePath, repo)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save repository cache", slog.Any("err", err))
	}

	if patchIDErr != nil {
		return nil, fmt.Errorf("failed to fully calculate patch id for commits: %w, saved %d", patchIDErr, patchIDCount)
	}

	return repo, nil
}

// getOrCreateIndex returns the index for a given commit hash.
// If the hash is new, it creates a new barebone commit and expands the graph structure to accommodate it.
func (r *Repository) getOrCreateIndex(hash SHA1) int {
	// Check if we've already assigned an index to this hash
	if idx, ok := r.hashToIndex[hash]; ok {
		return idx
	}

	idx := len(r.commits)
	r.commits = append(r.commits, &Commit{Hash: hash})
	r.hashToIndex[hash] = idx
	// Expand the commitGraph (adjacency list) to match the commits slice.
	r.commitGraph = append(r.commitGraph, nil)

	return idx
}

// buildCommitGraph builds the commit graph and associate commit details from scratch
// Returns a list of new commit indexes that don't have cached Patch IDs.
// The new commit list is in reverse chronological order based on commit date (the default for git log).
func (r *Repository) buildCommitGraph(ctx context.Context, cache *pb.RepositoryCache) ([]int, error) {
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
	var newCommits []int

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
		tags := []string{}

		switch len(commitInfo) {
		case 3:
			// tags are separated by commas
			rawRefs := strings.Split(commitInfo[2], ", ")
			for _, ref := range rawRefs {
				if ref == "" {
					continue
				}
				// Only keep tags
				if strings.HasPrefix(ref, "tag: ") {
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

		childIdx := r.getOrCreateIndex(childHash)
		commit := r.commits[childIdx]
		commit.Tags = tags

		// We want to keep the root commit (no parent) easily accessible for introduced=0
		if len(parentHashes) == 0 {
			r.rootCommits = append(r.rootCommits, childIdx)
		}

		// Add commit to graph (parent -> []child)
		for _, parentHash := range parentHashes {
			parentIdx := r.getOrCreateIndex(parentHash)
			commit.Parents = append(commit.Parents, parentIdx)

			r.commitGraph[parentIdx] = append(r.commitGraph[parentIdx], childIdx)
		}

		if patchID, ok := cachedPatchIDs[childHash]; ok {
			// Assign saved patch ID to commit details and map if found
			commit.PatchID = patchID
			// Also populate patchIDToCommits map
			r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], childIdx)
		} else {
			// Add to slice for patch ID to be generated later
			newCommits = append(newCommits, childIdx)
		}

		// Also populate the tag-to-commit map
		for _, tag := range tags {
			r.tagToCommit[tag] = childIdx
		}
	}

	logger.InfoContext(ctx, "Commit graph completed", slog.Int("new_commits", len(newCommits)), slog.Duration("duration", time.Since(start)))

	return newCommits, nil
}

// calculatePatchIDs calculates patch IDs only for the specific commits provided.
// Commits should be passed in order if possible. Processing linear commits sequentially improves performance slightly (in the 'git show' commands).
func (r *Repository) calculatePatchIDs(ctx context.Context, commits []int) error {
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
func (r *Repository) calculatePatchIDsWorker(ctx context.Context, chunk []int) error {
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
		for _, idx := range chunk {
			// Handle context cancel
			if ctx.Err() != nil {
				return
			}
			hash := r.commits[idx].Hash
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

// updatePatchID updates the PatchID for a given commit and adds it to the patchIDToCommits map.
func (r *Repository) updatePatchID(commitHash, patchID SHA1) {
	r.patchIDMu.Lock()
	defer r.patchIDMu.Unlock()

	idx, ok := r.hashToIndex[commitHash]
	if !ok {
		// This should never happen because we only call git patch-id on commits we see when building commit graph.
		return
	}
	commit := r.commits[idx]
	commit.PatchID = patchID

	r.patchIDToCommits[patchID] = append(r.patchIDToCommits[patchID], idx)
}

// parseHashes converts a slice of string hashes into a slice of commit indexes.
func (r *Repository) parseHashes(ctx context.Context, hashesStr []string) []int {
	indices := make([]int, 0, len(hashesStr))
	addedRoot := false // Only add root commits once if multiple intro=0 are provided

	for _, hash := range hashesStr {
		if hash == "0" {
			if !addedRoot {
				indices = append(indices, r.rootCommits...)
				addedRoot = true
			}

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

		h := SHA1(hashBytes)
		if idx, ok := r.hashToIndex[h]; ok {
			indices = append(indices, idx)
		} else {
			logger.ErrorContext(ctx, "commit hash not found in repository", slog.String("hash", hash))
		}
	}

	return indices
}

// hexHashes converts a slice of commit indices into a slice of their hex string hashes.
func (r *Repository) hexHashes(indices []int) []string {
	if len(indices) == 0 {
		return nil
	}
	hashes := make([]string, 0, len(indices))
	for _, idx := range indices {
		hashes = append(hashes, hex.EncodeToString(r.commits[idx].Hash[:]))
	}

	return hashes
}

// expandByCherrypick finds cherry picked commits that have the same Patch ID as the input commits.
// It returns a slice of commit indices of only the new commits
func (r *Repository) expandByCherrypick(commits []int) []int {
	// Track seen commits to avoid duplicates and exclude original input commits.
	seen := make([]bool, len(r.commits))
	for _, idx := range commits {
		seen[idx] = true
	}

	var cherrypicked []int
	for _, idx := range commits {
		pid := r.commits[idx].PatchID
		if pid == (SHA1{}) {
			// A commit made with --allow-empty could have no file diff and therefore a 0 patch ID
			continue
		}

		// Add equivalent commits with the same patch ID
		for _, eqIdx := range r.patchIDToCommits[pid] {
			if !seen[eqIdx] {
				seen[eqIdx] = true
				cherrypicked = append(cherrypicked, eqIdx)
			}
		}
	}

	return cherrypicked
}

// findAncestorRoots returns the subset of r.rootCommits that are ancestors of any of the input commits.
// It performs a BFS from the input fix commits to find reachable roots.
func (r *Repository) findAncestorRoots(from []int) []int {
	visited := make([]bool, len(r.commits))
	queue := make([]int, 0, len(from))
	foundRoots := make([]int, 0, len(r.rootCommits))

	for _, idx := range from {
		if !visited[idx] {
			visited[idx] = true
			queue = append(queue, idx)
		}
	}

	for len(queue) > 0 {
		if len(foundRoots) == len(r.rootCommits) {
			// All roots are found, we can terminate early
			break
		}

		curr := queue[0]
		queue = queue[1:]

		if len(r.commits[curr].Parents) == 0 {
			foundRoots = append(foundRoots, curr)
		}

		for _, pIdx := range r.commits[curr].Parents {
			if !visited[pIdx] {
				visited[pIdx] = true
				queue = append(queue, pIdx)
			}
		}
	}

	return foundRoots
}

type cherrypickedHashes struct {
	Introduced []string
	Fixed      []string
	Limit      []string
}

type resolvedEvents struct {
	// Introduced commits (from input) + cherrypicked intro commits (if enabled) + resolved roots (if there is intro=0)
	introduced []int
	// Fixed commits (from input) + children of last_affected commits (from input) + cherrypick of fixed commit (if enabled)
	allFixes []int
	// Cherrypicked commit hash strings (excluding original input commits)
	cherrypicked cherrypickedHashes
}

// resolveEvents parses and expands SeparatedEvents into lists of introduced and fixed commits
// In case of intro=0, it will not include root commits that are not ancestors of any fixed commits
func (r *Repository) resolveEvents(ctx context.Context, se *SeparatedEvents, cherrypickIntro, cherrypickFixed bool) resolvedEvents {
	// Parsing and expanding fixed events first because we need them to find relevant roots for intro=0
	fixed := r.parseHashes(ctx, se.Fixed)
	lastAffected := r.parseHashes(ctx, se.LastAffected)

	var cherrypickedFixedHashes []string
	// lastAffected should not be expanded because it does not imply a "fix" commit that can be cherrypicked to other branches
	if cherrypickFixed {
		newFixed := r.expandByCherrypick(fixed)
		cherrypickedFixedHashes = r.hexHashes(newFixed)
		fixed = append(fixed, newFixed...)
	}

	// Fixed commits and children of last affected are both in this list
	// For graph traversal sake they are both considered the fix
	allFixes := make([]int, 0, len(se.Fixed)+len(se.LastAffected))
	allFixes = append(allFixes, fixed...)
	for _, idx := range lastAffected {
		if idx < len(r.commitGraph) {
			allFixes = append(allFixes, r.commitGraph[idx]...)
		}
	}

	hasIntroZero := false
	filteredIntro := make([]string, 0, len(se.Introduced))
	for _, s := range se.Introduced {
		if s == "0" {
			hasIntroZero = true
		} else {
			filteredIntro = append(filteredIntro, s)
		}
	}

	introduced := r.parseHashes(ctx, filteredIntro)

	if hasIntroZero {
		if len(allFixes) > 0 {
			// If there are fixes, introduced=0 should only include root commits that are ancestors of the fixes
			introduced = append(introduced, r.findAncestorRoots(allFixes)...)
		} else {
			// If there are no fixes, then introduced=0 means all root commits
			introduced = append(introduced, r.rootCommits...)
		}
	}

	var cherrypickedIntroHashes []string
	if cherrypickIntro {
		newIntro := r.expandByCherrypick(introduced)
		cherrypickedIntroHashes = r.hexHashes(newIntro)
		introduced = append(introduced, newIntro...)
	}

	return resolvedEvents{
		introduced: introduced,
		allFixes:   allFixes,
		cherrypicked: cherrypickedHashes{
			Introduced: cherrypickedIntroHashes,
			Fixed:      cherrypickedFixedHashes,
		},
	}
}

// Affected returns a list of commits that are affected by the given introduced, fixed and last_affected events.
// It also returns two slices of hex hashes for newly identified cherry-picked introduced and fixed commits.
// A commit is affected when: from at least one introduced that is an ancestor of the commit, there is no path between them that passes through a fix.
// A fix can either be a fixed commit, or the children of a lastAffected commit.
func (r *Repository) Affected(ctx context.Context, se *SeparatedEvents, cherrypickIntro, cherrypickFixed bool) ([]*Commit, cherrypickedHashes) {
	logger.InfoContext(ctx, "Starting affected commits (all branches) walking")
	start := time.Now()

	resEvents := r.resolveEvents(ctx, se, cherrypickIntro, cherrypickFixed)
	introduced, allFixes := resEvents.introduced, resEvents.allFixes

	logger.DebugContext(ctx, "Resolved affected commit events to walk", slog.Any("introduced", introduced), slog.Any("allFixes", allFixes))

	fixedMap := make([]bool, len(r.commits))
	for _, idx := range allFixes {
		fixedMap[idx] = true
	}

	// The graph traversal
	// affectedMap deduplicates the affected commits from the graph walk from each introduced commit
	affectedMap := make([]bool, len(r.commits))

	// Preallocating the big slices, they will be cleared inside the per-intro graph walking
	queue := make([]int, 0, len(r.commits))
	affectedFromIntro := make([]bool, len(r.commits))
	updatedIdx := make([]int, 0, len(r.commits))
	unaffectable := make([]bool, len(r.commits))
	visited := make([]bool, len(r.commits))

	// Walk each introduced commit and find its affected commit
	for _, introIdx := range introduced {
		// BFS from intro
		queue = append(queue, introIdx)
		clear(affectedFromIntro)
		clear(updatedIdx)
		clear(unaffectable)
		clear(visited)

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			if visited[curr] {
				continue
			}
			visited[curr] = true

			// Descendant of a fixed commit
			if unaffectable[curr] {
				continue
			}

			// If we hit a fixed commit, its entire tree is treated as unaffectable
			// as any downstream commit can go through this fixed commit to become unaffected
			if fixedMap[curr] {
				unaffectable[curr] = true
				// Inline DFS from current (fixed) node to make all descendants as unaffected / unaffectable
				// 1. If a previous path added the descendant to affected list, remove it
				// 2. Add to the unaffectable set to block future paths
				stack := []int{curr}
				for len(stack) > 0 {
					unaffected := stack[len(stack)-1]
					stack = stack[:len(stack)-1]

					// Remove from affected list if it was reached via a previous non-fixed path.
					affectedFromIntro[unaffected] = false

					if unaffected < len(r.commitGraph) {
						for _, childIdx := range r.commitGraph[unaffected] {
							// Continue down the path if the child isn't already blocked.
							if !unaffectable[childIdx] {
								unaffectable[childIdx] = true
								stack = append(stack, childIdx)
							}
						}
					}
				}

				continue
			}

			// Otherwise, add to the intro-specific affected list and continue
			affectedFromIntro[curr] = true
			updatedIdx = append(updatedIdx, curr)
			if curr < len(r.commitGraph) {
				queue = append(queue, r.commitGraph[curr]...)
			}
		}

		// Add the final affected list of this introduced commit to the global set
		// We only look at the index that are updated in this loop
		for _, commitIdx := range updatedIdx {
			if affectedFromIntro[commitIdx] {
				affectedMap[commitIdx] = true
			}
		}
	}

	// Return the affected commit details
	affectedCommits := make([]*Commit, 0)
	for idx, affected := range affectedMap {
		if affected {
			affectedCommits = append(affectedCommits, r.commits[idx])
		}
	}

	logger.InfoContext(ctx, "Affected commits (all branches) walking completed", slog.Duration("duration", time.Since(start)), slog.Int("commit_count", len(affectedCommits)))

	return affectedCommits, resEvents.cherrypicked
}

// walkRevFirstParent walks backward from the walkFrom commits following the first parent until it hits an introduced commit.
// If a path does not encounter an introduced, it is discarded.
// Returns a list of affected commits
func (r *Repository) walkRevFirstParent(introduced []int, walkFrom []int) []*Commit {
	introMap := make([]bool, len(r.commits))
	for _, idx := range introduced {
		introMap[idx] = true
	}

	affectedMap := make([]bool, len(r.commits))

	// DFS to walk from walkFrom to introduced (follow first parent)
	for _, fromIdx := range walkFrom {
		stack := []int{fromIdx}
		var affectedPath []int
		pathValid := false

		for len(stack) > 0 {
			curr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			affectedPath = append(affectedPath, curr)

			// Stop traversal and keep affectedPath when:
			// 1. commit is introduced -> this path is a full path from walkFrom to introduced
			// 2. commit is already marked as affected -> this partial path is guaranteed to hit an introduced commit from curr
			if introMap[curr] || affectedMap[curr] {
				pathValid = true
				break
			}

			commit := r.commits[curr]
			// In git merge, first parent is the HEAD commit at the time of merge (on the branch that gets merged into)
			if len(commit.Parents) > 0 {
				stack = append(stack, commit.Parents[0])
			}
		}

		if pathValid {
			for _, idx := range affectedPath {
				affectedMap[idx] = true
			}
		}
	}

	var affectedCommits []*Commit
	for idx, isAffected := range affectedMap {
		if isAffected {
			affectedCommits = append(affectedCommits, r.commits[idx])
		}
	}

	return affectedCommits
}

// Limit walks and returns the commits that are strictly between introduced (inclusive) and limit (exclusive).
// It also returns two slices of hex hashes for newly identified cherry-picked introduced and limit commits.
func (r *Repository) Limit(ctx context.Context, se *SeparatedEvents, cherrypickIntro, cherrypickLimit bool) ([]*Commit, cherrypickedHashes) {
	logger.InfoContext(ctx, "Starting limit walking")
	start := time.Now()

	introduced := r.parseHashes(ctx, se.Introduced)
	limit := r.parseHashes(ctx, se.Limit)

	var cherrypickedIntroHashes []string
	var cherrypickedLimitHashes []string

	if cherrypickIntro {
		newIntro := r.expandByCherrypick(introduced)
		cherrypickedIntroHashes = r.hexHashes(newIntro)
		introduced = append(introduced, newIntro...)
	}
	if cherrypickLimit {
		newLimit := r.expandByCherrypick(limit)
		cherrypickedLimitHashes = r.hexHashes(newLimit)
		limit = append(limit, newLimit...)
	}

	// Walk from the first parent of limit, as limit commits are exclusive from affected range
	walkFrom := make([]int, 0, len(limit))
	for _, idx := range limit {
		commit := r.commits[idx]
		if len(commit.Parents) > 0 {
			walkFrom = append(walkFrom, commit.Parents[0])
		}
	}
	logger.DebugContext(ctx, "Resolved affected commit events to walk", slog.Any("introduced", introduced), slog.Any("walkFrom", walkFrom))

	affectedCommits := r.walkRevFirstParent(introduced, walkFrom)
	logger.InfoContext(ctx, "Limit walking completed", slog.Duration("duration", time.Since(start)), slog.Int("commit_count", len(affectedCommits)))

	return affectedCommits, cherrypickedHashes{
		Introduced: cherrypickedIntroHashes,
		Limit:      cherrypickedLimitHashes,
	}
}

// AffectedSingleBranch finds affected commits by walking backward from fixed and lastAffected commits to introduced commit following the first parent.
func (r *Repository) AffectedSingleBranch(ctx context.Context, se *SeparatedEvents) []*Commit {
	logger.InfoContext(ctx, "Starting affected commits (single branch) walking")
	start := time.Now()

	introduced := r.parseHashes(ctx, se.Introduced)
	fixed := r.parseHashes(ctx, se.Fixed)
	lastAffected := r.parseHashes(ctx, se.LastAffected)

	// Walk from the parent of fixed commits and lastAffected commits
	walkFrom := make([]int, 0, len(fixed)+len(lastAffected))
	for _, idx := range fixed {
		commit := r.commits[idx]
		if len(commit.Parents) > 0 {
			walkFrom = append(walkFrom, commit.Parents[0])
		}
	}
	walkFrom = append(walkFrom, lastAffected...)
	logger.DebugContext(ctx, "Resolved affected commit events to walk", slog.Any("introduced", introduced), slog.Any("walkFrom", walkFrom))

	affectedCommits := r.walkRevFirstParent(introduced, walkFrom)
	logger.InfoContext(ctx, "Affected commits (single branch) walking completed", slog.Duration("duration", time.Since(start)), slog.Int("commit_count", len(affectedCommits)))

	return affectedCommits
}

// runAndParseTags runs input command (git ls-remote or show-ref) and parses tags from stdout into repository structure
func (r *Repository) runAndParseTags(ctx context.Context, cmd *exec.Cmd) (map[string]SHA1, error) {
	logger.DebugContext(ctx, "Running git cmd and parsing tags", slog.String("cmd", cmd.String()))
	var stderr strings.Builder
	cmd.Stderr = &stderr

	stdout, errPipe := cmd.StdoutPipe()
	if errPipe != nil {
		return nil, errPipe
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(stdout)
	tagsMap := make(map[string]SHA1)

	for scanner.Scan() {
		// Both git ls-remote and show-ref return in the format:
		// "<hash> <ref/tags/tag-name>\n"
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		hashHex := fields[0]
		refRaw := fields[1]

		// This shouldn't happen with the --tags flag, but we will skip any non-tag refs just in case
		if !strings.HasPrefix(refRaw, "refs/tags/") {
			continue
		}

		tag := strings.TrimPrefix(refRaw, "refs/tags/")

		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil || len(hashBytes) != 20 {
			// We don't expect invalid hashes from git binary, this is a safeguard for the SHA1 type conversion below
			continue
		}

		tagsMap[tag] = SHA1(hashBytes)
	}

	if err := cmd.Wait(); err != nil {
		// git show-ref returns with exit code 1 if there is no tags (ls-remote return 0)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			logger.InfoContext(ctx, "No tags found (git show-ref exit code 1)")
			// We don't consider this an error and can just return the empty tagsMap
			return tagsMap, nil
		}

		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}

	logger.DebugContext(ctx, "Finished parsing tags", slog.Int("tags_count", len(tagsMap)))

	return tagsMap, nil
}

// GetLocalTags uses git show-ref to get tags from local git directory
func (r *Repository) GetLocalTags(ctx context.Context) (map[string]SHA1, error) {
	cmd := prepareCmd(ctx, r.repoPath, nil, "git", "show-ref", "--tags")

	return r.runAndParseTags(ctx, cmd)
}

// GetRemoteTags uses git ls-remote to get tags from remote git repository
func (r *Repository) GetRemoteTags(ctx context.Context) (map[string]SHA1, error) {
	cmd := prepareCmd(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"}, "git", "ls-remote", "--tags", "--quiet", r.URL)

	return r.runAndParseTags(ctx, cmd)
}
