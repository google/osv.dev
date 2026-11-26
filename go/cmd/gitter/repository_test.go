package main

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func runGit(t *testing.T, repoPath string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\nOutput: %s", args, err, out)
	}
}

// A very simple test repository with 3 commits and 2 tags.
func setupTagsTestRepo(t *testing.T, url string) string {
	t.Helper()
	gitStorePath = t.TempDir()
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("failed to create repo path %s: %v", repoPath, err)
	}

	runGit(t, repoPath, "init", "-b", "main")
	runGit(t, repoPath, "config", "user.email", "test@test.com")
	runGit(t, repoPath, "config", "user.name", "Test Name")

	// Commit 1
	err := os.WriteFile(filepath.Join(repoPath, "file1"), []byte("1"), 0600)
	if err != nil {
		t.Fatalf("failed to write file1 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file1")
	runGit(t, repoPath, "commit", "-m", "commit 1")

	// Commit 2 + Tag
	err = os.WriteFile(filepath.Join(repoPath, "file2"), []byte("2"), 0600)
	if err != nil {
		t.Fatalf("failed to write file2 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file2")
	runGit(t, repoPath, "commit", "-m", "commit 2")
	runGit(t, repoPath, "tag", "v1.0.0")

	// Commit 3 + Tag
	err = os.WriteFile(filepath.Join(repoPath, "file3"), []byte("3"), 0600)
	if err != nil {
		t.Fatalf("failed to write file3 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file3")
	runGit(t, repoPath, "commit", "-m", "commit 3")
	runGit(t, repoPath, "tag", "v1.1.0")

	return url
}

// An extremely simple test repository with 1 commit and no tags.
func setupEmptyTestRepo(t *testing.T, url string) string {
	t.Helper()
	gitStorePath = t.TempDir()
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("failed to create repo path %s: %v", repoPath, err)
	}

	runGit(t, repoPath, "init", "-b", "main")
	runGit(t, repoPath, "config", "user.email", "test@test.com")
	runGit(t, repoPath, "config", "user.name", "Test Name")

	err := os.WriteFile(filepath.Join(repoPath, "file1"), []byte("1"), 0600)
	if err != nil {
		t.Fatalf("failed to write file1 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file1")
	runGit(t, repoPath, "commit", "-m", "commit 1")

	return url
}

// A test repository with 1 lightweight tag and 1 annotated tag.
func setupAnnotatedTagsTestRepo(t *testing.T, url string) string {
	t.Helper()
	gitStorePath = t.TempDir()
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("failed to create repo path %s: %v", repoPath, err)
	}

	runGit(t, repoPath, "init", "-b", "main")
	runGit(t, repoPath, "config", "user.email", "test@test.com")
	runGit(t, repoPath, "config", "user.name", "Test Name")

	// Commit 1 + Lightweight Tag
	err := os.WriteFile(filepath.Join(repoPath, "file1"), []byte("1"), 0600)
	if err != nil {
		t.Fatalf("failed to write file1 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file1")
	runGit(t, repoPath, "commit", "-m", "commit 1")
	runGit(t, repoPath, "tag", "v1.0.0")

	// Commit 2 + Annotated Tag
	err = os.WriteFile(filepath.Join(repoPath, "file2"), []byte("2"), 0600)
	if err != nil {
		t.Fatalf("failed to write file2 for git repo setup: %v", err)
	}
	runGit(t, repoPath, "add", "file2")
	runGit(t, repoPath, "commit", "-m", "commit 2")
	runGit(t, repoPath, "tag", "-a", "v2.0.0", "-m", "release v2.0.0")

	return url
}

// setupFileDiffsTestRepo sets up a comprehensive test git repository containing:
// - Multiple branches (main, feature-branch) and tags (v1.0.0, v2.0.0)
// - Various git change types: addition (A), deletion (D), modification (M), rename (R), copy (C), type change (T)
// - Special character pathnames (spaces, quotes, tabs, Unicode/UTF-8 emojis) to test -z NUL handling
func setupFileDiffsTestRepo(t *testing.T, url string) string {
	t.Helper()
	gitStorePath = t.TempDir()
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	if err := os.MkdirAll(filepath.Join(repoPath, "subfolder"), 0755); err != nil {
		t.Fatalf("failed to create repo path %s: %v", repoPath, err)
	}

	runGit(t, repoPath, "init", "-b", "main")
	runGit(t, repoPath, "config", "user.email", "test@test.com")
	runGit(t, repoPath, "config", "user.name", "Test Name")

	// -------------------------------------------------------------------------
	// Commit 1: Baseline setup on main branch
	// -------------------------------------------------------------------------
	// Create baseline files that will be modified, deleted, renamed, copied, or type-changed later.
	err := os.WriteFile(filepath.Join(repoPath, "modified_file.txt"), []byte("initial modified content"), 0600)
	if err != nil {
		t.Fatalf("failed to write modified_file.txt: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "deleted_file.txt"), []byte("content to be deleted"), 0600)
	if err != nil {
		t.Fatalf("failed to write deleted_file.txt: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "old_name.txt"), []byte("content to be renamed"), 0600)
	if err != nil {
		t.Fatalf("failed to write old_name.txt: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "source_file.txt"), []byte("content to be copied"), 0600)
	if err != nil {
		t.Fatalf("failed to write source_file.txt: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "type_changed.txt"), []byte("regular file to symlink"), 0600)
	if err != nil {
		t.Fatalf("failed to write type_changed.txt: %v", err)
	}

	runGit(t, repoPath, "add", ".")
	runGit(t, repoPath, "commit", "-m", "commit 1: baseline")
	runGit(t, repoPath, "tag", "v1.0.0")

	// -------------------------------------------------------------------------
	// Commit 2: Switch to feature-branch and perform various git file changes
	// -------------------------------------------------------------------------
	runGit(t, repoPath, "checkout", "-b", "feature-branch")

	// 1. Addition (A): Add new files, including special characters (spaces, quotes, tabs, Unicode/UTF-8)
	err = os.WriteFile(filepath.Join(repoPath, "added_file.txt"), []byte("newly added content"), 0600)
	if err != nil {
		t.Fatalf("failed to write added_file.txt: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "Spaces &\"quotes\" in name.txt"), []byte("special char content"), 0600)
	if err != nil {
		t.Fatalf("failed to write special char file: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "esacpe\nchar\tin\rname\aAHHHH.txt"), []byte("escape char content"), 0600)
	if err != nil {
		t.Fatalf("failed to write special char file: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "unicode_filenǟme_multibyte_utf8_ˁ˚ᴥ˚ˀ_🔥🏴󠁧󠁢󠁥󠁮󠁧󠁿👩🏻‍✈️.json"), []byte("{\"status\": \"ok\"}"), 0600)
	if err != nil {
		t.Fatalf("failed to write unicode file: %v", err)
	}
	err = os.WriteFile(filepath.Join(repoPath, "subfolder", "nested.txt"), []byte("subfolder file content"), 0600)
	if err != nil {
		t.Fatalf("failed to write subfolder/nested.txt: %v", err)
	}

	// 2. Modification (M): Change content of modified_file.txt
	err = os.WriteFile(filepath.Join(repoPath, "modified_file.txt"), []byte("updated modified content"), 0600)
	if err != nil {
		t.Fatalf("failed to update modified_file.txt: %v", err)
	}

	// 3. Deletion (D): Delete deleted_file.txt
	runGit(t, repoPath, "rm", "deleted_file.txt")

	// 4. Rename (R): Rename old_name.txt -> new_name.txt
	runGit(t, repoPath, "mv", "old_name.txt", "new_name.txt")

	// 5. Copy (C): Duplicate source_file.txt into copied_file.txt
	err = os.WriteFile(filepath.Join(repoPath, "copied_file.txt"), []byte("content to be copied"), 0600)
	if err != nil {
		t.Fatalf("failed to write copied_file.txt: %v", err)
	}

	// 6. Type change (T): Convert type_changed.txt into a symlink pointing to modified_file.txt
	_ = os.Remove(filepath.Join(repoPath, "type_changed.txt"))
	if err := os.Symlink("modified_file.txt", filepath.Join(repoPath, "type_changed.txt")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	runGit(t, repoPath, "add", ".")
	runGit(t, repoPath, "commit", "-m", "commit 2: feature changes")
	runGit(t, repoPath, "tag", "v2.0.0")

	// -------------------------------------------------------------------------
	// Switch back to main and set HEAD
	// -------------------------------------------------------------------------
	runGit(t, repoPath, "checkout", "main")
	// Symbolic ref origin/HEAD would have been set to remote's default branch when it is cloned
	// But in our local test repo, we need to explicitly set this ref
	runGit(t, repoPath, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/main")

	return url
}

func TestBuildCommitGraph(t *testing.T) {
	url := setupTagsTestRepo(t, "git://test-repo.git")
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, url)

	newCommits, err := r.buildCommitGraph(ctx, nil)

	if err != nil {
		t.Fatalf("buildCommitGraph failed: %v", err)
	}

	if len(newCommits) != 3 {
		t.Errorf("expected 3 new commits, got %d", len(newCommits))
	}

	if len(r.commits) != 3 {
		t.Errorf("expected 3 commits, got %d", len(r.commits))
	}

	// 2 tags
	if len(r.tagToCommit) != 2 {
		t.Errorf("expected 2 tags, got %d", len(r.tagToCommit))
	}
}

func TestCalculatePatchIDs(t *testing.T) {
	url := setupTagsTestRepo(t, "git://test-repo.git")
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, url)

	newCommits, err := r.buildCommitGraph(ctx, nil)
	if err != nil {
		t.Fatalf("buildCommitGraph failed: %v", err)
	}

	err = r.calculatePatchIDs(ctx, newCommits)
	if err != nil {
		t.Fatalf("calculatePatchIDs failed: %v", err)
	}

	// Verify all commits have patch IDs
	for _, idx := range newCommits {
		commit := r.commits[idx]
		if commit.PatchID == [20]byte{} {
			t.Errorf("missing patch ID for commit %s", printSHA1(commit.Hash))
		}
	}
}

func TestLoadRepository(t *testing.T) {
	url := setupTagsTestRepo(t, "git://test-repo.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	ctx := context.WithValue(t.Context(), urlKey, url)

	// First loadRepository with a brand new repo
	r1, err := LoadRepository(ctx, repoPath)
	if err != nil {
		t.Fatalf("First LoadRepository failed: %v", err)
	}

	// Verify cache file is created
	cachePath := repoPath + ".pb"
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("expected cache file to be created")
	}

	// A second loadRepoistory has hit the test
	r2, err := LoadRepository(ctx, repoPath)
	if err != nil {
		t.Fatalf("Second LoadRepository failed: %v", err)
	}

	// Check that the two sets of Patch IDs are the same
	for idx, commit := range r1.commits {
		if commit.PatchID != r2.commits[idx].PatchID {
			t.Errorf("patch ID mismatch for commit %s", printSHA1(commit.Hash))
		}
	}
}

// For test setup
func (r *Repository) addEdgeForTest(parent, child SHA1) {
	pIdx := r.getOrCreateIndex(parent)
	cIdx := r.getOrCreateIndex(child)
	r.commitGraph[pIdx] = append(r.commitGraph[pIdx], cIdx)
	r.commits[cIdx].Parents = append(r.commits[cIdx].Parents, pIdx)
}

func (r *Repository) addTagForTest(hash SHA1, tag string) {
	idx := r.getOrCreateIndex(hash)
	r.commits[idx].Tags = append(r.commits[idx].Tags, tag)
	r.tagToCommit[tag] = idx
}

func (r *Repository) markBranchHeadForTest(hash SHA1) {
	idx := r.getOrCreateIndex(hash)
	r.branchHeads[idx] = struct{}{}
}

// Helper to decode string into SHA1
func decodeSHA1(s string) SHA1 {
	var hash SHA1
	// Pad with zeros because the test strings are shorter than 40 char
	padded := strings.Repeat("0", 40-len(s)) + s
	b, err := hex.DecodeString(padded)
	if err != nil {
		panic(err)
	}
	copy(hash[:], b)

	return hash
}

// Helper to encode SHA1 into string
func encodeSHA1(hash SHA1) string {
	return hex.EncodeToString(hash[:])
}

// Helper to pretty print SHA1 as string (leading 0's removed)
func printSHA1(hash SHA1) string {
	// Remove padding zeros for a cleaner results
	str := hex.EncodeToString(hash[:])

	return strings.TrimLeft(str, "0")
}

// cmpSHA1Opts are applied to the cmp.Diff function to make the output more readable
// 1. Transform SHA1s to pretty strings
// 2. Sorts slices to ensure deterministic comparisons
var cmpSHA1Opts = []cmp.Option{
	cmp.Transformer("SHA1s", func(in []SHA1) []string {
		out := make([]string, len(in))
		for i, h := range in {
			out[i] = printSHA1(h)
		}

		return out
	}),
	cmpopts.SortSlices(func(a, b string) bool {
		return a < b
	}),
}

func TestExpandByCherrypick(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Commit hashes
	h1 := decodeSHA1("aaaa")
	h2 := decodeSHA1("bbbb")
	h3 := decodeSHA1("cccc")

	// Patch ID
	p1 := decodeSHA1("1111")

	// Setup commit details
	idx1 := repo.getOrCreateIndex(h1)
	idx2 := repo.getOrCreateIndex(h2)
	idx3 := repo.getOrCreateIndex(h3)

	repo.commits[idx1].PatchID = p1
	repo.commits[idx3].PatchID = p1 // h3 has the same patch ID as h1 should be cherry picked

	// Setup patch ID map
	repo.patchIDToCommits[p1] = []int{idx1, idx3}

	tests := []struct {
		name     string
		input    []int
		expected []SHA1
	}{
		{
			name:     "Expand single commit with cherry-pick",
			input:    []int{idx1},
			expected: []SHA1{h3},
		},
		{
			name:     "No expansion for commit without cherry-pick",
			input:    []int{idx2},
			expected: []SHA1{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdxs := repo.expandByCherrypick(tt.input)
			var got []SHA1
			for _, idx := range gotIdxs {
				got = append(got, repo.commits[idx].Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("expandByCherrypick() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Testing cases with introduced and fixed only.
func TestAffected_Introduced_Fixed(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//            -> F -> G
	//           /
	// A -> B -> C -> D -> E
	//      \        /
	//       -> H ->

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hB, hH)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hC, hF)
	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hH, hD)
	repo.rootCommits = []int{0} // Root commit is A

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "Linear: A introduced, B fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hB)},
			},
			expected: []SHA1{hA},
		},
		{
			name: "Branch propagation: A introduced, C fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hC)},
			},
			expected: []SHA1{hA, hB, hH},
		},
		{
			name: "Re-introduced: (A,C) introduced, (B,D,G) fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA), encodeSHA1(hC)},
				Fixed:      []string{encodeSHA1(hB), encodeSHA1(hD), encodeSHA1(hG)},
			},
			expected: []SHA1{hA, hC, hF},
		},
		{
			name: "Merge intro: H introduced, E fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hH)},
				Fixed:      []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hH, hD},
		},
		{
			name: "Merge fix: A introduced, H fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hH)},
			},
			expected: []SHA1{hA, hB, hC, hF, hG},
		},
		{
			name: "Merge intro and fix (different branches): C introduced, H fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hC)},
				Fixed:      []string{encodeSHA1(hH)},
			},
			expected: []SHA1{hC, hD, hE, hF, hG},
		},
		{
			name: "Introduced = 0: C fixed",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(hC)},
			},
			expected: []SHA1{hA, hB, hH},
		},
		{
			name: "Introduced = 0: no fix",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
			},
			expected: []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, AffectedWalkOptions{})

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_Introduced_Fixed() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffected_Introduced_LastAffected(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//            -> F -> G
	//           /
	// A -> B -> C -> D -> E
	//      \        /
	//       -> H ->

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hB, hH)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hC, hF)
	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hH, hD)
	repo.rootCommits = []int{0} // Root commit is A

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "Linear: D introduced, E lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hD)},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hD, hE},
		},
		{
			name: "Branch propagation: A introduced, C lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				LastAffected: []string{encodeSHA1(hC)},
			},
			expected: []SHA1{hA, hB, hC, hH},
		},
		{
			name: "Re-introduced: (A,D) introduced, (B,E) lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA), encodeSHA1(hD)},
				LastAffected: []string{encodeSHA1(hB), encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hD, hE},
		},
		{
			name: "Merge intro: H introduced, D lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hH)},
				LastAffected: []string{encodeSHA1(hD)},
			},
			expected: []SHA1{hH, hD},
		},
		{
			name: "Merge lastAffected: A introduced, H lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				LastAffected: []string{encodeSHA1(hH)},
			},
			expected: []SHA1{hA, hB, hC, hF, hG, hH},
		},
		{
			name: "Merge intro and lastAffected (different branches): C introduced, H lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hC)},
				LastAffected: []string{encodeSHA1(hH)},
			},
			expected: []SHA1{hC, hF, hG},
		},
		{
			name: "Introduced = 0: C lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				LastAffected: []string{encodeSHA1(hC)},
			},
			expected: []SHA1{hA, hB, hC, hH},
		},
		{
			name: "Introduced = 0: no fix",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
			},
			expected: []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, AffectedWalkOptions{})

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_Introduced_LastAffected() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Testing with both fixed and lastAffected
func TestAffected_Combined(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//            -> F -> G
	//           /
	// A -> B -> C -> D -> E
	//      \        /
	//       -> H ->

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hB, hH)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hC, hF)
	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hH, hD)

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "Branching out: C introduced, G fixed, D lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hC)},
				Fixed:        []string{encodeSHA1(hG)},
				LastAffected: []string{encodeSHA1(hD)},
			},
			expected: []SHA1{hC, hD, hF},
		},
		{
			name: "Redundant Blocking: A introduced, B fixed, E lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				Fixed:        []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA},
		},
		{
			name: "Introduced=Fixed: No affected commit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hB)},
				Fixed:      []string{encodeSHA1(hB)},
			},
			expected: []SHA1{},
		},
		{
			name: "Introduced=lastAffected: Only current commit affected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hB)},
			},
			expected: []SHA1{hB},
		},
		{
			name: "Fixed=lastAffected: Stop at fix, lastAffected no effect",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				Fixed:        []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hB)},
			},
			expected: []SHA1{hA},
		},
		{
			// This is the current behaviour as we treat child of lastAffected commit as a fixed commit
			name: "Intro=lastAffected+1: commit not affected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA), encodeSHA1(hC)}, // C is the child of B
				LastAffected: []string{encodeSHA1(hB)},
			},
			expected: []SHA1{hA, hB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, AffectedWalkOptions{})

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_Combined() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffected_Cherrypick(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	// A -> B -> C -> D
	// |				 |
	// | (cherrypick)
	// | 				 |
	// E -> F -> G -> H

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	c1 := decodeSHA1("c1")
	c2 := decodeSHA1("c2")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hE, hF)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hG, hH)

	// Setup PatchID map for cherrypicking
	idxA := repo.getOrCreateIndex(hA)
	idxE := repo.getOrCreateIndex(hE)
	repo.patchIDToCommits[c1] = []int{idxA, idxE}
	idxC := repo.getOrCreateIndex(hC)
	idxG := repo.getOrCreateIndex(hG)
	repo.patchIDToCommits[c2] = []int{idxC, idxG}

	repo.commits[idxA].PatchID = c1
	repo.commits[idxE].PatchID = c1
	repo.commits[idxC].PatchID = c2
	repo.commits[idxG].PatchID = c2
	repo.rootCommits = []int{idxA, idxE}

	tests := []struct {
		name                      string
		se                        *SeparatedEvents
		cherrypickIntro           bool
		cherrypickFixed           bool
		expectedCommits           []SHA1
		expectedCherrypickedIntro []string
		expectedCherrypickedFixed []string
	}{
		{
			name: "Cherrypick Introduced Only: A introduced, G fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro:           true,
			cherrypickFixed:           false,
			expectedCommits:           []SHA1{hA, hB, hC, hD, hE, hF},
			expectedCherrypickedIntro: []string{encodeSHA1(hE)},
			expectedCherrypickedFixed: nil,
		},
		{
			name: "Cherrypick Fixed Only: A introduced, G fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro:           false,
			cherrypickFixed:           true,
			expectedCommits:           []SHA1{hA, hB},
			expectedCherrypickedIntro: nil,
			expectedCherrypickedFixed: []string{encodeSHA1(hC)},
		},
		{
			name: "Cherrypick Introduced and Fixed: A introduced, G fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro:           true,
			cherrypickFixed:           true,
			expectedCommits:           []SHA1{hA, hB, hE, hF},
			expectedCherrypickedIntro: []string{encodeSHA1(hE)},
			expectedCherrypickedFixed: []string{encodeSHA1(hC)},
		},
		{
			name: "Cherrypick Introduced=0: G fixed",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro:           true,
			cherrypickFixed:           true,
			expectedCommits:           []SHA1{hA, hB, hE, hF},
			expectedCherrypickedIntro: nil,
			expectedCherrypickedFixed: []string{encodeSHA1(hC)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, res := repo.Affected(t.Context(), tt.se, AffectedWalkOptions{
				CherrypickIntroduced: tt.cherrypickIntro,
				CherrypickFixed:      tt.cherrypickFixed,
			})
			gotIntro, gotFixed := res.Introduced, res.Fixed

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expectedCommits, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_Cherrypick() commits mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.expectedCherrypickedIntro, gotIntro); diff != "" {
				t.Errorf("TestAffected_Cherrypick() intro mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.expectedCherrypickedFixed, gotFixed); diff != "" {
				t.Errorf("TestAffected_Cherrypick() fixed mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLimit(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	// A -> B -> C -> D -> E
	//      \
	//       -> F -> G -> H

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hB, hF)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hG, hH)
	repo.rootCommits = []int{0} // A is root commit

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "One branch: A introduced, D limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Limit:      []string{encodeSHA1(hD)},
			},
			expected: []SHA1{hA, hB, hC},
		},
		{
			name: "Side branch: A introduced, G limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Limit:      []string{encodeSHA1(hG)},
			},
			expected: []SHA1{hA, hB, hF},
		},
		{
			name: "Two branches: A introduced, (D,G) limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Limit:      []string{encodeSHA1(hD), encodeSHA1(hG)},
			},
			expected: []SHA1{hA, hB, hC, hF},
		},
		{
			name: "Introduced=0, G limit",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Limit:      []string{encodeSHA1(hG)},
			},
			expected: []SHA1{hA, hB, hF},
		},
		{
			name: "Multiple limits on same branch: A introduced, (C,E) limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Limit:      []string{encodeSHA1(hC), encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB},
		},
		{
			name: "Re-introduced with multiple limits on same branch: (A,D) introduced, (C,E) limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA), encodeSHA1(hD)},
				Limit:      []string{encodeSHA1(hC), encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Limit(t.Context(), tt.se, false, false)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestLimit() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLimit_Cherrypick(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	// A -> B -> C -> D
	// 			|	   |
	//   (cherrypick)
	//  		|		 |
	// E -> F -> G -> H

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	c1 := decodeSHA1("c1")
	c2 := decodeSHA1("c2")

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hE, hF)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hG, hH)

	// Setup PatchID map for cherrypicking
	idxB := repo.getOrCreateIndex(hB)
	idxF := repo.getOrCreateIndex(hF)
	repo.patchIDToCommits[c1] = []int{idxB, idxF}
	idxC := repo.getOrCreateIndex(hC)
	idxG := repo.getOrCreateIndex(hG)
	repo.patchIDToCommits[c2] = []int{idxC, idxG}

	idxA := repo.getOrCreateIndex(hA)
	idxE := repo.getOrCreateIndex(hE)
	repo.rootCommits = []int{idxA, idxE}

	repo.commits[idxB].PatchID = c1
	repo.commits[idxF].PatchID = c1
	repo.commits[idxC].PatchID = c2
	repo.commits[idxG].PatchID = c2

	tests := []struct {
		name            string
		se              *SeparatedEvents
		cherrypickIntro bool
		cherrypickLimit bool
		expected        []SHA1
	}{
		{
			name: "Cherrypick Introduced Only: B introduced, G limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hB)},
				Limit:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro: true,
			cherrypickLimit: false,
			expected:        []SHA1{hF},
		},
		{
			name: "Cherrypick Limit Only: B introduced, G limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hB)},
				Limit:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro: false,
			cherrypickLimit: true,
			expected:        []SHA1{hB},
		},
		{
			name: "Cherrypick Introduced and Limit: A introduced, G limit",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Limit:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro: true,
			cherrypickLimit: true,
			expected:        []SHA1{hA, hB},
		},
		{
			name: "Cherrypick Introduced=0: G limit",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Limit:      []string{encodeSHA1(hG)},
			},
			cherrypickIntro: true,
			cherrypickLimit: true,
			expected:        []SHA1{hA, hB, hE, hF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, res := repo.Limit(t.Context(), tt.se, tt.cherrypickIntro, tt.cherrypickLimit)
			gotIntro, gotLimit := res.Introduced, res.Limit

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			// Check affected commits
			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestLimit_Cherrypick() commits mismatch (-want +got):\n%s", diff)
			}

			// Check cherrypicked events
			var expectedIntro []string
			var expectedLimit []string
			if tt.cherrypickIntro && tt.se.Introduced[0] == encodeSHA1(hB) {
				expectedIntro = append(expectedIntro, encodeSHA1(hF))
			}
			if tt.cherrypickLimit && tt.se.Limit[0] == encodeSHA1(hG) {
				expectedLimit = append(expectedLimit, encodeSHA1(hC))
			}

			if diff := cmp.Diff(expectedIntro, gotIntro); diff != "" {
				t.Errorf("TestLimit_Cherrypick() intro mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(expectedLimit, gotLimit); diff != "" {
				t.Errorf("TestLimit_Cherrypick() limit mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveEvents_MultipleRoots(t *testing.T) {
	repo := NewRepository("/repo")

	// Commit graph has 4 roots, 3 disconnected trees
	// Tree 1:
	// A -> B -> C
	// Tree 2:
	// D -> E -> F
	// Tree 3 (Multiple Roots):
	// G --\
	//      -> I -> J
	// H --/

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("adad")
	hH := decodeSHA1("aeae")
	hJ := decodeSHA1("afaf")
	hK := decodeSHA1("bcbc")

	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)

	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hE, hF)

	repo.addEdgeForTest(hG, hJ)
	repo.addEdgeForTest(hH, hJ)
	repo.addEdgeForTest(hJ, hK)

	idxA := repo.getOrCreateIndex(hA)
	idxD := repo.getOrCreateIndex(hD)
	idxG := repo.getOrCreateIndex(hG)
	idxH := repo.getOrCreateIndex(hH)
	repo.rootCommits = []int{idxA, idxD, idxG, idxH}

	tests := []struct {
		name          string
		se            *SeparatedEvents
		expectedIntro []int
	}{
		{
			name: "Introduced=0, No fix: Resolves to all roots",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
			},
			expectedIntro: []int{idxA, idxD, idxG, idxH},
		},
		{
			name: "Introduced=0, Fix in Tree 2: Resolves to Root D only",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(hE)},
			},
			expectedIntro: []int{idxD},
		},
		{
			name: "Introduced=0, LastAffected in Tree 1: Resolves to Root A only",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				LastAffected: []string{encodeSHA1(hB)},
			},
			expectedIntro: []int{idxA},
		},
		{
			name: "Introduced=0, Leaf LastAffected in Tree 1: Resolves to Root A only",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				LastAffected: []string{encodeSHA1(hC)},
			},
			expectedIntro: []int{idxA},
		},
		{
			name: "Introduced=0, Fix at J: Resolves to both root G and H",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(hJ)},
			},
			expectedIntro: []int{idxG, idxH},
		},
		{
			name: "No introduced=0: Do not resolve",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hE)},
			},
			expectedIntro: []int{idxA},
		},
		{
			name: "Introduced=0, Mixed Fixed and LastAffected: Resolves to both Root A and Root D",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				Fixed:        []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expectedIntro: []int{idxA, idxD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := repo.resolveEvents(t.Context(), tt.se, AffectedWalkOptions{})
			gotIntro := res.introduced

			if diff := cmp.Diff(tt.expectedIntro, gotIntro, cmpopts.SortSlices(func(a, b int) bool { return a < b })); diff != "" {
				t.Errorf("TestResolveEvents_MultipleRoots() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffectedSingleBranch(t *testing.T) {
	repo := NewRepository("/repo")

	// Graph: (Parent -> Child)
	//            -> F -> G
	//           /
	// A -> B -> C -> D -> E
	//      \        /
	//       -> H ->

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	hI := decodeSHA1("adad") // This hash is not in the graph

	// Setup graph (Parent -> Children)
	repo.addEdgeForTest(hA, hB)
	repo.addEdgeForTest(hB, hC)
	repo.addEdgeForTest(hB, hH)
	repo.addEdgeForTest(hC, hD)
	repo.addEdgeForTest(hC, hF)
	repo.addEdgeForTest(hD, hE)
	repo.addEdgeForTest(hF, hG)
	repo.addEdgeForTest(hH, hD)
	repo.rootCommits = []int{0} // A is root commit

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "Only follow first parent (fixed): A introduced, G fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hG)},
			},
			expected: []SHA1{hA, hB, hC, hF},
		},
		{
			name: "Only follow first parent (last affected): A introduced, D lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				LastAffected: []string{encodeSHA1(hD)},
			},
			expected: []SHA1{hA, hB, hC, hD},
		},
		{
			name: "Intro and fix not on same branch -> nothing affected: H introduce, G fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hH)},
				Fixed:      []string{encodeSHA1(hG)},
			},
			expected: []SHA1{},
		},
		{
			name: "Fix not found in graph -> nothing affected: A introduce, I fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hI)},
			},
			expected: []SHA1{},
		},
		{
			name: "lastAffected has no children: A introduced, E lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hC, hD, hE},
		},
		{
			name: "introduced=0, E fixed",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hC, hD},
		},
		{
			name: "introduced=0, E lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hC, hD, hE},
		},
		{
			name: "Multiple fixes on same branch: A introduced, (C,E) fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA)},
				Fixed:      []string{encodeSHA1(hC), encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB},
		},
		{
			name: "Re-introduced on same branch: (A,D) introduced, (C,E) fixed",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(hA), encodeSHA1(hD)},
				Fixed:      []string{encodeSHA1(hC), encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB, hD},
		},
		{
			name: "Two bounding events (fixed -> lastAffected): A introduced, B fixed, E lastAffected",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				Fixed:        []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA},
		},
		{
			name: "Two bounding events (lastAffected -> fixed): A introduced, B lastAffected, E fixed",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				LastAffected: []string{encodeSHA1(hB)},
				Fixed:        []string{encodeSHA1(hE)},
			},
			expected: []SHA1{hA, hB},
		},
		{
			name: "Fixed=lastAffected: Stop at fix, lastAffected no effect",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(hA)},
				Fixed:        []string{encodeSHA1(hB)},
				LastAffected: []string{encodeSHA1(hB)},
			},
			expected: []SHA1{hA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits := repo.AffectedSingleBranch(t.Context(), tt.se)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffectedSingleBranch() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test runAndParseTags() with mock stdout
func TestRunAndParseTags(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *exec.Cmd
		want    map[string]SHA1
		wantErr bool
	}{
		{
			name: "Parse mock data",
			cmd:  exec.Command("echo", "000000000000000000000000000000000000aaaa refs/tags/v1.0.0\n000000000000000000000000000000000000bbbb refs/tags/v1.1.0\n"),
			want: map[string]SHA1{
				"v1.0.0": decodeSHA1("aaaa"),
				"v1.1.0": decodeSHA1("bbbb"),
			},
		},
		{
			name: "Stdout contains ref/heads and tags, should filter out non-tags",
			cmd:  exec.Command("printf", "000000000000000000000000000000000000aaaa refs/tags/v1.0.0\n000000000000000000000000000000000000cccc refs/heads/main\n"),
			want: map[string]SHA1{
				"v1.0.0": decodeSHA1("aaaa"),
			},
		},
		{
			name: "Annotated tag resolves to peeled commit hash and omits ^{}",
			cmd:  exec.Command("printf", "000000000000000000000000000000000000aaaa refs/tags/v1.0.0\n000000000000000000000000000000000000bbbb refs/tags/v1.0.0^{}\n"),
			want: map[string]SHA1{
				"v1.0.0": decodeSHA1("bbbb"),
			},
		},
		{
			name: "Mixed lightweight and annotated tags",
			cmd:  exec.Command("printf", "0000000000000000000000000000000000001111 refs/tags/v1.0.0\n0000000000000000000000000000000000002222 refs/tags/v2.0.0\n0000000000000000000000000000000000003333 refs/tags/v2.0.0^{}\n"),
			want: map[string]SHA1{
				"v1.0.0": decodeSHA1("1111"),
				"v2.0.0": decodeSHA1("3333"),
			},
		},
		{
			name: "Annotated tag resolves to peeled commit hash regardless of output order (peeled ref first)",
			cmd:  exec.Command("printf", "000000000000000000000000000000000000bbbb refs/tags/v1.0.0^{}\n000000000000000000000000000000000000aaaa refs/tags/v1.0.0\n"),
			want: map[string]SHA1{
				"v1.0.0": decodeSHA1("bbbb"),
			},
		},
		{
			// git show-ref returns exit code 1 when there are no tags, so make sure we don't throw error in this case
			name: "Exit code 1 (no tags)",
			cmd:  exec.Command("bash", "-c", "exit 1"),
			want: map[string]SHA1{},
		},
		{
			name:    "Exit code 128 (actual error)",
			cmd:     exec.Command("bash", "-c", "echo 'some error' >&2; exit 128"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Repository{}
			got, err := r.runAndParseTags(t.Context(), tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runAndParseTags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("runAndParseTags() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestGetLocalTags(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T, url string) string
		wantTags  []string
		wantCount int
	}{
		{
			name:      "Repo with tags",
			setupFunc: setupTagsTestRepo,
			wantTags:  []string{"v1.0.0", "v1.1.0"},
			wantCount: 2,
		},
		{
			name:      "Repo with annotated and lightweight tags",
			setupFunc: setupAnnotatedTagsTestRepo,
			wantTags:  []string{"v1.0.0", "v2.0.0"},
			wantCount: 2,
		},
		{
			name:      "Empty repo (no tags)",
			setupFunc: setupEmptyTestRepo,
			wantTags:  []string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.setupFunc(t, "git://test-repo.git")
			r := NewRepository(url)
			ctx := context.WithValue(t.Context(), urlKey, url)

			tags, err := r.GetLocalTags(ctx)
			if err != nil {
				t.Fatalf("GetLocalTags failed: %v", err)
			}

			if len(tags) != tt.wantCount {
				t.Errorf("expected %d tags, got %d", tt.wantCount, len(tags))
			}

			for _, wantTag := range tt.wantTags {
				if _, ok := tags[wantTag]; !ok {
					t.Errorf("expected tag %s to exist", wantTag)
				}
			}

			// Ensure no tag contains ^{} suffix
			for tag := range tags {
				if strings.HasSuffix(tag, "^{}") {
					t.Errorf("unexpected peeled tag suffix in tag: %s", tag)
				}
			}

			if tt.name == "Repo with annotated and lightweight tags" {
				commit2SHA, err := r.resolveCommit(ctx, "v2.0.0")
				if err != nil {
					t.Fatalf("failed to resolve commit for v2.0.0: %v", err)
				}
				if tags["v2.0.0"] != decodeSHA1(commit2SHA) {
					t.Errorf("annotated tag v2.0.0 hash mismatch: got %x, want %s", tags["v2.0.0"], commit2SHA)
				}
			}
		})
	}
}

func TestGetRemoteTags(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T, url string) string
		wantTags  []string
		wantCount int
	}{
		{
			name:      "Repo with tags",
			setupFunc: setupTagsTestRepo,
			wantTags:  []string{"v1.0.0", "v1.1.0"},
			wantCount: 2,
		},
		{
			name:      "Repo with annotated and lightweight tags",
			setupFunc: setupAnnotatedTagsTestRepo,
			wantTags:  []string{"v1.0.0", "v2.0.0"},
			wantCount: 2,
		},
		{
			name:      "Empty repo (no tags)",
			setupFunc: setupEmptyTestRepo,
			wantTags:  []string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.setupFunc(t, "git://test-repo.git")
			repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
			r := NewRepository(url)
			// Overwriting URL with repoPath to simulate remote repo without needing to query an actual repo url
			r.URL = r.repoPath
			ctx := context.WithValue(t.Context(), urlKey, repoPath)

			tags, err := r.GetRemoteTags(ctx)
			if err != nil {
				t.Fatalf("GetRemoteTags failed: %v", err)
			}

			if len(tags) != tt.wantCount {
				t.Errorf("expected %d tags, got %d", tt.wantCount, len(tags))
			}

			for _, wantTag := range tt.wantTags {
				if _, ok := tags[wantTag]; !ok {
					t.Errorf("expected tag %s to exist", wantTag)
				}
			}

			// Ensure no tag contains ^{} suffix
			for tag := range tags {
				if strings.HasSuffix(tag, "^{}") {
					t.Errorf("unexpected peeled tag suffix in tag: %s", tag)
				}
			}

			if tt.name == "Repo with annotated and lightweight tags" {
				commit2SHA, err := r.resolveCommit(ctx, "v2.0.0")
				if err != nil {
					t.Fatalf("failed to resolve commit for v2.0.0: %v", err)
				}
				if tags["v2.0.0"] != decodeSHA1(commit2SHA) {
					t.Errorf("annotated tag v2.0.0 hash mismatch: got %x, want %s", tags["v2.0.0"], commit2SHA)
				}
			}
		})
	}
}

func TestParseNameStatusLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    *FileChange
		wantErr bool
	}{
		{
			name: "Added file",
			line: "A\tpath/to/added.txt",
			want: &FileChange{From: "", To: "path/to/added.txt"},
		},
		{
			name: "Deleted file",
			line: "D\tpath/to/deleted.txt",
			want: &FileChange{From: "path/to/deleted.txt", To: ""},
		},
		{
			name: "Modified file",
			line: "M\tpath/to/modified.txt",
			want: &FileChange{From: "path/to/modified.txt", To: "path/to/modified.txt"},
		},
		{
			name: "Type changed file",
			line: "T\tpath/to/symlink",
			want: &FileChange{From: "path/to/symlink", To: "path/to/symlink"},
		},
		{
			name: "Renamed file",
			line: "R100\told/path.txt\tnew/path.txt",
			want: &FileChange{From: "old/path.txt", To: "new/path.txt"},
		},
		{
			name: "Copied file",
			line: "C90\tsrc/path.txt\tdst/path.txt",
			want: &FileChange{From: "", To: "dst/path.txt"},
		},
		{
			name: "Quoted path with escaped spaces and quotes",
			line: "A\t\"Spaces &\\\"quotes\\\" in name.txt\"",
			want: &FileChange{From: "", To: "Spaces &\"quotes\" in name.txt"},
		},
		{
			name: "Quoted path with C-style escape characters",
			line: "A\t\"esacpe\\nchar\\tin\\rname\\aAHHHH.txt\"",
			want: &FileChange{From: "", To: "esacpe\nchar\tin\rname\aAHHHH.txt"},
		},
		{
			name: "Quoted path with octal NUL byte escape sequence",
			line: "A\t\"file_with_\\000_nul.txt\"",
			want: &FileChange{From: "", To: "file_with_\x00_nul.txt"},
		},
		{
			name: "Quoted path with octal byte escape sequences",
			line: "A\t\"unicode_filename_utf8_\\360\\237\\224\\245.json\"",
			want: &FileChange{From: "", To: "unicode_filename_utf8_🔥.json"},
		},
		{
			name: "Quoted path with backslashes",
			line: "A\t\"path\\\\to\\\\file.txt\"",
			want: &FileChange{From: "", To: "path\\to\\file.txt"},
		},
		{
			name: "Renamed file with quoted paths and escapes",
			line: "R100\t\"old_\\n_name.txt\"\t\"new_\\r_name.txt\"",
			want: &FileChange{From: "old_\n_name.txt", To: "new_\r_name.txt"},
		},
		{
			name:    "Invalid format - missing tab",
			line:    "A path/to/file",
			wantErr: true,
		},
		{
			name:    "Rename missing dst",
			line:    "R100\told/path.txt",
			wantErr: true,
		},
		{
			name:    "Unknown status letter",
			line:    "X\tpath/to/file",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNameStatusLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseNameStatusLine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(FileChange{})); diff != "" {
					t.Errorf("parseNameStatusLine() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestListFileDiffs(t *testing.T) {
	url := setupFileDiffsTestRepo(t, "git://test-repo-file-diffs.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, repoPath)

	commit1, err := r.resolveCommit(ctx, "v1.0.0")
	if err != nil {
		t.Fatalf("resolve commit v1.0.0: %v", err)
	}
	commit2, err := r.resolveCommit(ctx, "v2.0.0")
	if err != nil {
		t.Fatalf("resolve commit v2.0.0: %v", err)
	}

	// Test ListFileDiffs between commit1 (v1.0.0) and branch target (feature-branch)
	latestCommit, changes, err := r.ListFileDiffs(ctx, commit1, "feature-branch")
	if err != nil {
		t.Fatalf("ListFileDiffs failed: %v", err)
	}

	if latestCommit != commit2 {
		t.Errorf("expected latestCommit %s, got %s", commit2, latestCommit)
	}

	// Expected changes in feature-branch since v1.0.0:
	// Added (A): added_file.txt, copied_file.txt, Spaces &"quotes" in name.txt, unicode_filename_utf8_🔥.json, subfolder/nested.txt
	// Deleted (D): deleted_file.txt
	// Modified (M): modified_file.txt
	// Renamed (R): old_name.txt -> new_name.txt
	// Type changed (T): type_changed.txt -> type_changed.txt
	wantChanges := []*FileChange{
		{From: "", To: "added_file.txt"},
		{From: "", To: "copied_file.txt"},
		{From: "", To: "esacpe\nchar\tin\rname\aAHHHH.txt"},
		{From: "", To: "Spaces &\"quotes\" in name.txt"},
		{From: "", To: "unicode_filenǟme_multibyte_utf8_ˁ˚ᴥ˚ˀ_🔥🏴󠁧󠁢󠁥󠁮󠁧󠁿👩🏻‍✈️.json"},
		{From: "", To: "subfolder/nested.txt"},
		{From: "deleted_file.txt", To: ""},
		{From: "modified_file.txt", To: "modified_file.txt"},
		{From: "old_name.txt", To: "new_name.txt"},
		{From: "type_changed.txt", To: "type_changed.txt"},
	}

	opts := cmpopts.SortSlices(func(a, b *FileChange) bool {
		if a.From != b.From {
			return a.From < b.From
		}

		return a.To < b.To
	})

	if diff := cmp.Diff(wantChanges, changes, opts, cmp.AllowUnexported(FileChange{})); diff != "" {
		t.Errorf("ListFileDiffs changes mismatch (-want +got):\n%s", diff)
	}

	// Test ListFileDiffs with empty lastSyncCommit (diff against empty tree)
	_, emptyCommitChanges, err := r.ListFileDiffs(ctx, "", "feature-branch")
	if err != nil {
		t.Fatalf("ListFileDiffs with empty lastSyncCommit failed: %v", err)
	}
	if len(emptyCommitChanges) == 0 {
		t.Errorf("expected non-empty changes for empty lastSyncCommit, got 0")
	}
	for _, c := range emptyCommitChanges {
		if c.From != "" {
			t.Errorf("expected From path to be empty when diffing against empty tree, got %q", c.From)
		}
	}

	// Test with invalid lastSyncCommit
	_, _, err = r.ListFileDiffs(ctx, "invalidhash123", "feature-branch")
	if err == nil {
		t.Error("expected error for invalid lastSyncCommit, got nil")
	}
}

func TestGetFileContent(t *testing.T) {
	url := setupFileDiffsTestRepo(t, "git://test-repo-content.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, repoPath)

	commit1, err := r.resolveCommit(ctx, "v1.0.0")
	if err != nil {
		t.Fatalf("resolve v1.0.0: %v", err)
	}
	commit2, err := r.resolveCommit(ctx, "v2.0.0")
	if err != nil {
		t.Fatalf("resolve v2.0.0: %v", err)
	}

	tests := []struct {
		name        string
		ref         string
		path        string
		wantContent string
		wantErr     bool
	}{
		{
			name:        "Fetch file content at v1.0.0 baseline",
			ref:         commit1,
			path:        "modified_file.txt",
			wantContent: "initial modified content",
			wantErr:     false,
		},
		{
			name:        "Fetch modified file content at v2.0.0",
			ref:         commit2,
			path:        "modified_file.txt",
			wantContent: "updated modified content",
			wantErr:     false,
		},
		{
			name:        "Fetch file with spaces and quotes in name",
			ref:         commit2,
			path:        "Spaces &\"quotes\" in name.txt",
			wantContent: "special char content",
			wantErr:     false,
		},
		{
			name:        "Fetch file with escape characters in name",
			ref:         commit2,
			path:        "esacpe\nchar\tin\rname\aAHHHH.txt",
			wantContent: "escape char content",
			wantErr:     false,
		},
		{
			name:        "Fetch file when path input is quoted and escaped",
			ref:         commit2,
			path:        "\"esacpe\\nchar\\tin\\rname\\aAHHHH.txt\"",
			wantContent: "escape char content",
			wantErr:     false,
		},
		{
			name:        "Fetch file when path input has quoted spaces and quotes",
			ref:         commit2,
			path:        "\"Spaces &\\\"quotes\\\" in name.txt\"",
			wantContent: "special char content",
			wantErr:     false,
		},
		{
			name:        "Fetch file with Unicode UTF-8 emoji in name",
			ref:         commit2,
			path:        "unicode_filenǟme_multibyte_utf8_ˁ˚ᴥ˚ˀ_🔥🏴󠁧󠁢󠁥󠁮󠁧󠁿👩🏻‍✈️.json",
			wantContent: "{\"status\": \"ok\"}",
			wantErr:     false,
		},
		{
			name:        "Fetch nested file in subfolder",
			ref:         commit2,
			path:        "subfolder/nested.txt",
			wantContent: "subfolder file content",
			wantErr:     false,
		},
		{
			name:    "Fetch deleted file at v2.0.0 (should fail)",
			ref:     commit2,
			path:    "deleted_file.txt",
			wantErr: true,
		},
		{
			name:    "Fetch directory instead of file (should fail)",
			ref:     commit2,
			path:    "subfolder",
			wantErr: true,
		},
		{
			name:    "Fetch with invalid commit ref (should fail)",
			ref:     "invalid-ref",
			path:    "modified_file.txt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.GetFileContent(ctx, tt.ref, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetFileContent(%q, %q) error = %v, wantErr %v", tt.ref, tt.path, err, tt.wantErr)
			}
			if !tt.wantErr {
				if string(got) != tt.wantContent {
					t.Errorf("GetFileContent(%q, %q) got %q, want %q", tt.ref, tt.path, string(got), tt.wantContent)
				}
			}
		})
	}
}

func TestResolveCommit(t *testing.T) {
	url := setupFileDiffsTestRepo(t, "git://test-repo-resolve.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, repoPath)

	branchSha, err := r.resolveCommit(ctx, "feature-branch")
	if err != nil || len(branchSha) != 40 {
		t.Fatalf("setup resolve commit feature-branch failed: %v", err)
	}

	tests := []struct {
		name    string
		ref     string
		wantSha string
		wantErr bool
	}{
		{
			name:    "Resolve tag",
			ref:     "v1.0.0",
			wantErr: false,
		},
		{
			name:    "Resolve full branch ref",
			ref:     "refs/heads/feature-branch",
			wantSha: branchSha,
			wantErr: false,
		},
		{
			name:    "Resolve short branch name",
			ref:     "feature-branch",
			wantSha: branchSha,
			wantErr: false,
		},
		{
			name:    "Resolve full 40-char commit SHA",
			ref:     branchSha,
			wantSha: branchSha,
			wantErr: false,
		},
		{
			name:    "Resolve abbr commit SHA",
			ref:     branchSha[:7],
			wantSha: branchSha,
			wantErr: false,
		},
		{
			name:    "Resolve origin/HEAD",
			ref:     "origin/HEAD",
			wantErr: false,
		},
		{
			name:    "Resolve nonexistent branch name",
			ref:     "nonexistent-branch",
			wantErr: true,
		},
		{
			name:    "Resolve empty ref string",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.resolveCommit(ctx, tt.ref)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveCommit(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(got) != 40 {
					t.Errorf("ResolveCommit(%q) returned SHA length %d, expected 40", tt.ref, len(got))
				}
				if tt.wantSha != "" && got != tt.wantSha {
					t.Errorf("ResolveCommit(%q) got %q, want %q", tt.ref, got, tt.wantSha)
				}
			}
		})
	}
}

func TestListCommits(t *testing.T) {
	url := setupFileDiffsTestRepo(t, "git://test-repo-list-commits.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))
	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, repoPath)

	commit1, err := r.resolveCommit(ctx, "v1.0.0")
	if err != nil {
		t.Fatalf("resolve commit v1.0.0: %v", err)
	}
	commit2, err := r.resolveCommit(ctx, "v2.0.0")
	if err != nil {
		t.Fatalf("resolve commit v2.0.0: %v", err)
	}

	tests := []struct {
		name             string
		targetBranch     string
		lastSyncedCommit string
		lastSyncedTime   time.Time
		newestFirst      bool
		includePaths     []string
		excludePaths     []string
		wantBranch       string
		wantHead         string
		wantCommitsCount int
		wantErr          bool
		check            func(t *testing.T, commits []*CommitDiff)
	}{
		{
			name:             "Default branch resolution and range query",
			targetBranch:     "",
			lastSyncedTime:   time.Unix(1, 0),
			wantBranch:       "main",
			wantHead:         commit1,
			wantCommitsCount: 1,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				if commits[0].Commit != commit1 {
					t.Errorf("expected commit %q, got %q", commit1, commits[0].Commit)
				}
			},
		},
		{
			name:             "Specific branch with lastSyncedCommit",
			targetBranch:     "feature-branch",
			lastSyncedCommit: commit1,
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 1,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				c := commits[0]
				if c.Commit != commit2 {
					t.Errorf("expected commit %q, got %q", commit2, c.Commit)
				}
				if !strings.Contains(c.Message, "commit 2: feature changes") {
					t.Errorf("unexpected message: %q", c.Message)
				}
				if len(c.FilesChanged) == 0 {
					t.Errorf("expected files changed, got 0")
				}
				if c.Patch == "" {
					t.Errorf("expected non-empty patch")
				}
			},
		},
		{
			name:             "Zero commits when lastSyncedCommit equals HEAD",
			targetBranch:     "feature-branch",
			lastSyncedCommit: commit2,
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 0,
		},
		{
			name:             "Empty boundaries queries full branch history",
			targetBranch:     "feature-branch",
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 2,
		},
		{
			name:             "Non-ancestor without lastSyncedTime returns error",
			targetBranch:     "main",
			lastSyncedCommit: commit2,
			wantErr:          true,
		},
		{
			name:             "Non-ancestor with lastSyncedTime falls back to lastSyncedTime",
			targetBranch:     "main",
			lastSyncedCommit: commit2,
			lastSyncedTime:   time.Unix(1, 0),
			wantBranch:       "main",
			wantHead:         commit1,
			wantCommitsCount: 1,
		},
		{
			name:             "Ordering chronological (default oldest first)",
			targetBranch:     "feature-branch",
			lastSyncedTime:   time.Unix(1, 0),
			newestFirst:      false,
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 2,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				if commits[0].Commit != commit1 || commits[1].Commit != commit2 {
					t.Errorf("expected chronological order [commit1, commit2], got [%s, %s]",
						commits[0].Commit, commits[1].Commit)
				}
			},
		},
		{
			name:             "Ordering newest_first",
			targetBranch:     "feature-branch",
			lastSyncedTime:   time.Unix(1, 0),
			newestFirst:      true,
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 2,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				if commits[0].Commit != commit2 || commits[1].Commit != commit1 {
					t.Errorf("expected reverse chronological order [commit2, commit1], got [%s, %s]",
						commits[0].Commit, commits[1].Commit)
				}
			},
		},
		{
			name:             "Path filtering with include_paths",
			targetBranch:     "feature-branch",
			lastSyncedCommit: commit1,
			includePaths:     []string{"modified_file.txt"},
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 1,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				if len(commits[0].FilesChanged) != 1 {
					t.Fatalf("expected exactly 1 file changed, got %d", len(commits[0].FilesChanged))
				}
				if commits[0].FilesChanged[0].To != "modified_file.txt" {
					t.Errorf("expected modified_file.txt, got %q", commits[0].FilesChanged[0].To)
				}
			},
		},
		{
			name:             "Path filtering with exclude_paths",
			targetBranch:     "feature-branch",
			lastSyncedCommit: commit1,
			excludePaths:     []string{"modified_file.txt"},
			wantBranch:       "feature-branch",
			wantHead:         commit2,
			wantCommitsCount: 1,
			check: func(t *testing.T, commits []*CommitDiff) {
				t.Helper()
				for _, fc := range commits[0].FilesChanged {
					if fc.To == "modified_file.txt" || fc.From == "modified_file.txt" {
						t.Errorf("expected modified_file.txt to be excluded, but found it in files changed")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			branch, head, commits, err := r.ListCommits(ctx, tt.targetBranch, tt.lastSyncedCommit, tt.lastSyncedTime, tt.newestFirst, tt.includePaths, tt.excludePaths)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListCommits() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if branch != tt.wantBranch {
				t.Errorf("branch = %q, want %q", branch, tt.wantBranch)
			}
			if head != tt.wantHead {
				t.Errorf("head = %q, want %q", head, tt.wantHead)
			}
			if len(commits) != tt.wantCommitsCount {
				t.Fatalf("len(commits) = %d, want %d", len(commits), tt.wantCommitsCount)
			}
			if tt.check != nil {
				tt.check(t, commits)
			}
		})
	}
}

func TestParseCommitsLogPatchTruncation(t *testing.T) {
	ctx := t.Context()
	sampleLog := []byte("\x1e---COMMIT-METADATA---\n" +
		"abcd1234abcd1234abcd1234abcd1234abcd1234\n" +
		"1700000000\n" +
		"feat: add large dataset\n" +
		"\x00---COMMIT-DIFF---\n" +
		":100644 100644 5be4a4a 0000000 M\tlarge_file.txt\n" +
		"diff --git a/large_file.txt b/large_file.txt\n" +
		"--- a/large_file.txt\n" +
		"+++ b/large_file.txt\n" +
		"@@ -1,3 +1,3 @@\n" +
		"+Line 1: this is a huge patch hunk\n" +
		"+Line 2: another line of data\n" +
		"+Line 3: yet another line of data\n")

	// Parse with a tiny limit (20 bytes) to force truncation for testing
	commits := parseCommitsLog(ctx, sampleLog, 20)
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}

	c := commits[0]
	if c.Commit != "abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Errorf("unexpected commit hash: %s", c.Commit)
	}
	if len(c.FilesChanged) != 1 || c.FilesChanged[0].To != "large_file.txt" {
		t.Errorf("FilesChanged was lost or corrupted: %+v", c.FilesChanged)
	}
	if !c.PatchTruncated {
		t.Errorf("expected PatchTruncated to be true")
	}
	if !strings.Contains(c.Patch, "[Diff truncated: exceeded max patch size of 20 bytes]") {
		t.Errorf("expected truncation notice in patch, got: %s", c.Patch)
	}
}

func TestParseCommitsLogInvalidUTF8(t *testing.T) {
	ctx := t.Context()
	// Create a patch with a multi-byte UTF-8 emoji ("🚀" = 4 bytes: 0xF0, 0x9F, 0x99, 0x80)
	// and truncate right in the middle of the rune bytes.
	prefix := "diff --git a/a.txt b/a.txt\n+🚀"
	rawBytes := []byte("\x1e---COMMIT-METADATA---\n" +
		"abcd1234abcd1234abcd1234abcd1234abcd1234\n" +
		"1700000000\n" +
		"feat: \xff\xfe non-utf8 commit msg\n" +
		"\x00---COMMIT-DIFF---\n" +
		prefix + " trailing content\n")

	// Cut halfway through the 🚀 emoji
	cutLimit := len("diff --git a/a.txt b/a.txt\n+") + 2
	commits := parseCommitsLog(ctx, rawBytes, cutLimit)
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}

	// Verify both message and patch produce valid UTF-8 strings
	if !utf8.ValidString(commits[0].Message) {
		t.Errorf("commit message contains invalid UTF-8: %q", commits[0].Message)
	}
	if !utf8.ValidString(commits[0].Patch) {
		t.Errorf("truncated patch contains invalid UTF-8: %q", commits[0].Patch)
	}
}

func TestParseCommitsLogEmptyCommit(t *testing.T) {
	ctx := t.Context()
	rawBytes := []byte("\x1e---COMMIT-METADATA---\n" +
		"abcd1234abcd1234abcd1234abcd1234abcd1234\n" +
		"1700000000\n" +
		"chore: empty commit\n" +
		"\x00---COMMIT-DIFF---\n")

	commits := parseCommitsLog(ctx, rawBytes, DefaultMaxCommitPatchBytes)
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit for empty-diff commit, got %d", len(commits))
	}
	if commits[0].Commit != "abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Errorf("unexpected commit hash: %s", commits[0].Commit)
	}
	if len(commits[0].FilesChanged) != 0 {
		t.Errorf("expected no changed files, got %d", len(commits[0].FilesChanged))
	}
	if commits[0].Patch != "" {
		t.Errorf("expected empty patch, got %q", commits[0].Patch)
	}
}

func TestBuildCommitGraph_BranchHeads(t *testing.T) {
	url := setupTagsTestRepo(t, "git://test-branch-heads.git")
	repoPath := filepath.Join(gitStorePath, getRepoDirName(url))

	// Create an off-branch tag-only release spur off v1.0.0 (detached HEAD)
	runGit(t, repoPath, "checkout", "--detach", "v1.0.0")
	if err := os.WriteFile(filepath.Join(repoPath, "version.txt"), []byte("1.0.1"), 0600); err != nil {
		t.Fatalf("failed to write version.txt: %v", err)
	}
	runGit(t, repoPath, "add", "version.txt")
	runGit(t, repoPath, "commit", "-m", "release v1.0.1 on spur")
	runGit(t, repoPath, "tag", "v1.0.1")
	// Return to main so v1.0.1 has only a tag ref (no branch/HEAD ref)
	runGit(t, repoPath, "checkout", "main")

	r := NewRepository(url)
	ctx := context.WithValue(t.Context(), urlKey, url)
	if _, err := r.buildCommitGraph(ctx, nil); err != nil {
		t.Fatalf("buildCommitGraph failed: %v", err)
	}

	// v1.1.0 is at the head of main (has branch ref + tag) -> in branchHeads, NOT a tag-only chain
	v110Idx, ok := r.tagToCommit["v1.1.0"]
	if !ok {
		t.Fatal("missing tag v1.1.0")
	}
	if _, ok := r.branchHeads[v110Idx]; !ok {
		t.Errorf("expected v1.1.0 (head of main) to be marked in branchHeads")
	}
	if r.isTagOnlyChain(v110Idx, defaultResolveTagSpurMaxLength) {
		t.Errorf("expected v1.1.0 (head of main) not to be a tag-only chain")
	}

	// v1.0.1 is on a detached spur (tag-only, 0 children) -> not in branchHeads, IS a tag-only chain
	v101Idx, ok := r.tagToCommit["v1.0.1"]
	if !ok {
		t.Fatal("missing tag v1.0.1")
	}
	if _, ok := r.branchHeads[v101Idx]; ok {
		t.Errorf("expected v1.0.1 (tag-only spur) not to be marked in branchHeads")
	}
	if !r.isTagOnlyChain(v101Idx, defaultResolveTagSpurMaxLength) {
		t.Errorf("expected v1.0.1 (tag-only spur) to be a tag-only chain")
	}

	// v1.0.0 is an interior commit (has children) -> findTagSpurFork returns false
	v100Idx, ok := r.tagToCommit["v1.0.0"]
	if !ok {
		t.Fatal("missing tag v1.0.0")
	}
	if _, _, ok := r.findTagSpurFork(v100Idx, defaultResolveTagSpurMaxLength); ok {
		t.Errorf("expected findTagSpurFork(v1.0.0) to return false for interior commit")
	}

	// findTagSpurFork(v1.0.1) with default maxLength=1 should resolve directly to v1.0.0
	forkIdx, spurEntry, ok := r.findTagSpurFork(v101Idx, defaultResolveTagSpurMaxLength)
	if !ok {
		t.Fatal("expected findTagSpurFork(v1.0.1) to succeed")
	}
	if forkIdx != v100Idx {
		t.Errorf("findTagSpurFork(v1.0.1) forkIdx = %d, want %d (v1.0.0)", forkIdx, v100Idx)
	}
	if spurEntry != v101Idx {
		t.Errorf("findTagSpurFork(v1.0.1) spurEntry = %d, want %d (v1.0.1)", spurEntry, v101Idx)
	}
}

func TestAffected_ResolveTagSpur_SingleCommit(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//                     -> tag0 [v1.0.0]   -> tag1 [v1.0.1]             -> tag2 [v1.0.2]    -> tag3 [v1.0.3]
	//                    /                  /                            /                   /
	// main0 [v1.0.0-dev] -----------> main1 ----------------------> main2 [v1.0.2-dev] ----> main3 [branchHead]
	//                    \
	//                     -> rc0 [v1.0.0RC1]

	main0, main1, main2, main3 := decodeSHA1("b0"), decodeSHA1("b1"), decodeSHA1("b2"), decodeSHA1("b3")
	tag0, tag1, tag2, tag3 := decodeSHA1("10"), decodeSHA1("11"), decodeSHA1("12"), decodeSHA1("13")
	rc0 := decodeSHA1("c0")

	repo.addEdgeForTest(main0, main1)
	repo.addEdgeForTest(main1, main2)
	repo.addEdgeForTest(main2, main3)
	repo.addEdgeForTest(main0, tag0)
	repo.addEdgeForTest(main0, rc0)
	repo.addEdgeForTest(main1, tag1)
	repo.addEdgeForTest(main2, tag2)
	repo.addEdgeForTest(main3, tag3)
	repo.addTagForTest(main0, "v1.0.0-dev")
	repo.addTagForTest(main2, "v1.0.2-dev")
	repo.addTagForTest(tag0, "v1.0.0")
	repo.addTagForTest(rc0, "v1.0.0RC1")
	repo.addTagForTest(tag1, "v1.0.1")
	repo.addTagForTest(tag2, "v1.0.2")
	repo.addTagForTest(tag3, "v1.0.3")
	repo.markBranchHeadForTest(main3)
	repo.rootCommits = []int{repo.hashToIndex[main0]}

	tests := []struct {
		name     string
		se       *SeparatedEvents
		opts     AffectedWalkOptions
		expected []SHA1
	}{
		{
			name: "Disabled: tag spur leaf cannot reach main branch (no regression)",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{},
			expected: []SHA1{tag0},
		},
		{
			name: "Both enabled (default maxLength=1): anchors tag0 to main0 and stops at tag2 and main3",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2},
		},
		{
			name: "Both enabled (maxLength=5): branchHead on main3 prevents main3->tag3 from being skipped",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2},
		},
		{
			name: "Introduced only: walks main branch but tag2 does not block main3",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2, main3, tag3},
		},
		{
			name: "Fixed only with introduced=0: stops at tag2 and main3",
			se: &SeparatedEvents{
				Introduced: []string{"0"},
				Fixed:      []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurFixed: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2},
		},
		{
			name: "LastAffected only with introduced=0: keeps tag2 affected and stops at main3",
			se: &SeparatedEvents{
				Introduced:   []string{"0"},
				LastAffected: []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurLastAffected: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2, tag2},
		},
		{
			name: "Introduced and LastAffected enabled: keeps tag2 affected and stops at main3",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(tag0)},
				LastAffected: []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurLastAffected: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2, tag2},
		},
		{
			name: "Fixed flag alone does not resolve last_affected tag spur",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(tag0)},
				LastAffected: []string{encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2, tag2, main3, tag3},
		},
		{
			name: "Adjacent regression with last_affected (LAST_AFFECTED tag0, INTRODUCED tag1, LAST_AFFECTED tag2)",
			se: &SeparatedEvents{
				Introduced:   []string{"0", encodeSHA1(tag1)},
				LastAffected: []string{encodeSHA1(tag0), encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurLastAffected: true},
			expected: []SHA1{main0, tag0, rc0, main1, tag1, main2, tag2},
		},
		{
			name: "Same-fork introduced (rc0) and fixed (tag0): keeps main0 and rc0 affected",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(rc0)},
				Fixed:      []string{encodeSHA1(tag0)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true},
			expected: []SHA1{main0, rc0},
		},
		{
			name: "Adjacent regression spurs (FIXED tag0, INTRODUCED tag1, FIXED tag2)",
			se: &SeparatedEvents{
				Introduced: []string{"0", encodeSHA1(tag1)},
				Fixed:      []string{encodeSHA1(tag0), encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true},
			expected: []SHA1{main0, rc0, main1, tag1, main2},
		},
		{
			name: "Adjacent on-branch regression (FIXED tag0, INTRODUCED main1, FIXED tag2)",
			se: &SeparatedEvents{
				Introduced: []string{"0", encodeSHA1(main1)},
				Fixed:      []string{encodeSHA1(tag0), encodeSHA1(tag2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurFixed: true},
			expected: []SHA1{main0, rc0, main1, tag1, main2},
		},
		{
			name: "On-branch interior tagged commits (flags disabled)",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(main0)},
				Fixed:      []string{encodeSHA1(main2)},
			},
			opts:     AffectedWalkOptions{},
			expected: []SHA1{main0, tag0, rc0, main1, tag1},
		},
		{
			name: "On-branch interior tagged commits (flags enabled, unchanged)",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(main0)},
				Fixed:      []string{encodeSHA1(main2)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{main0, tag0, rc0, main1, tag1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, tt.opts)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_ResolveTagSpur_SingleCommit() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffected_ResolveTagSpur_MultiCommit(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	// main0 -------------------> main1 -------------------> main2 [branchHead]
	//      \                          \
	//       -> spur0 -> tag0 [v1.0.0]  -> spur1 -> spur2 [branchHead] -> tag1 [v1.0.1]
	//           \                          \
	//            -> rc0a -> rc0 [v1.0.0RC7] -> rc1 [v1.0.1RC1]

	main0, main1, main2 := decodeSHA1("b0"), decodeSHA1("b1"), decodeSHA1("b2")
	spur0, tag0, rc0a, rc0 := decodeSHA1("a0"), decodeSHA1("10"), decodeSHA1("c2"), decodeSHA1("c3")
	spur1, spur2, tag1, rc1 := decodeSHA1("a1"), decodeSHA1("a2"), decodeSHA1("11"), decodeSHA1("c1")

	repo.addEdgeForTest(main0, main1)
	repo.addEdgeForTest(main1, main2)
	repo.addEdgeForTest(main0, spur0)
	repo.addEdgeForTest(spur0, tag0)
	repo.addEdgeForTest(spur0, rc0a)
	repo.addEdgeForTest(rc0a, rc0)
	repo.addEdgeForTest(main1, spur1)
	repo.addEdgeForTest(spur1, spur2)
	repo.addEdgeForTest(spur2, tag1)
	repo.addEdgeForTest(spur1, rc1)

	repo.addTagForTest(tag0, "v1.0.0")
	repo.addTagForTest(rc0, "v1.0.0RC7")
	repo.addTagForTest(tag1, "v1.0.1")
	repo.addTagForTest(rc1, "v1.0.1RC1")
	repo.markBranchHeadForTest(spur2)
	repo.markBranchHeadForTest(main2)

	tests := []struct {
		name     string
		se       *SeparatedEvents
		opts     AffectedWalkOptions
		expected []SHA1
	}{
		{
			name: "Default maxLength=1 stops at spur0 (2-commit rc0a->rc0 exceeds limit)",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true},
			expected: []SHA1{spur0, tag0, rc0a, rc0},
		},
		{
			name: "MaxLength=2: 2-commit spur0->tag0 resolves to main0, 3-commit spur1->spur2->tag1 does not",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 2},
			expected: []SHA1{main0, spur0, tag0, rc0a, rc0, main1, spur1, spur2, rc1, main2},
		},
		{
			name: "MaxLength=3: 3-commit spur1->spur2->tag1 resolves to main1 and blocks main2",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 3},
			expected: []SHA1{main0, spur0, tag0, rc0a, rc0, main1, spur1, spur2, rc1},
		},
		{
			name: "MaxLength=5: skips nested RC chains on both introduced and fixed spurs",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{main0, spur0, tag0, rc0a, rc0, main1, spur1, spur2, rc1},
		},
		{
			name: "Shared patch spur (rc1 -> tag1) stays scoped to spur1 due to branchHead on spur2",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(rc1)},
				Fixed:      []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{spur1, rc1, spur2},
		},
		{
			name: "INTRODUCED == FIXED on the same tag spur returns empty",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(tag0)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{},
		},
		{
			name: "FIXED on fork commit (main0) preserves child INTRODUCED tag spur (tag0)",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag0)},
				Fixed:      []string{encodeSHA1(main0)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{tag0},
		},
		{
			name: "Multi-commit LAST_AFFECTED (tag1): keeps spur1..tag1 affected and blocks main2",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(tag0)},
				LastAffected: []string{encodeSHA1(tag1)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurLastAffected: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{main0, spur0, tag0, rc0a, rc0, main1, spur1, spur2, rc1, tag1},
		},
		{
			name: "INTRODUCED == LAST_AFFECTED on the same tag spur returns only tag0",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(tag0)},
				LastAffected: []string{encodeSHA1(tag0)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurLastAffected: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{tag0},
		},
		{
			name: "FIXED == LAST_AFFECTED on the same tag spur: fixed wins and blocks main1",
			se: &SeparatedEvents{
				Introduced:   []string{encodeSHA1(main0)},
				Fixed:        []string{encodeSHA1(tag0)},
				LastAffected: []string{encodeSHA1(tag0)},
			},
			opts:     AffectedWalkOptions{ResolveTagSpurFixed: true, ResolveTagSpurLastAffected: true, ResolveTagSpurMaxLength: 5},
			expected: []SHA1{main0, spur0, rc0a, rc0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, tt.opts)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_ResolveTagSpur_MultiCommit() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffected_ResolveTagSpur_MultiBranch(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//               -> tag100 [v1.0.0, branchHead]          prFix
	//              /                                         \ (Parents[1]: PR merged into spur)
	// rel0 -------+-----------> rel1 ----------------------> spurMerge -> tag101 [v1.0.1, branchHead]
	//                            |\ (Parents[0])
	//                            | \-> rel2 [branchHead] -> untagged
	//                            \ (Parents[1]: upward merge into dev)
	// dev0 ----------------------> dev1 -> dev2 [branchHead]

	rel0, rel1, rel2, untagged := decodeSHA1("b0"), decodeSHA1("b1"), decodeSHA1("b2"), decodeSHA1("f1")
	tag100, prFix, spurMerge, tag101 := decodeSHA1("10"), decodeSHA1("e0"), decodeSHA1("e1"), decodeSHA1("11")
	dev0, dev1, dev2 := decodeSHA1("d0"), decodeSHA1("d1"), decodeSHA1("d2")

	repo.addEdgeForTest(rel0, rel1)
	repo.addEdgeForTest(rel1, rel2)
	repo.addEdgeForTest(rel2, untagged)
	repo.addEdgeForTest(rel0, tag100)
	// Add rel1 -> spurMerge first so rel1 is Parents[0] and prFix is Parents[1].
	repo.addEdgeForTest(rel1, spurMerge)
	repo.addEdgeForTest(prFix, spurMerge)
	repo.addEdgeForTest(spurMerge, tag101)
	// Add dev0 -> dev1 first so dev0 is Parents[0] and rel1 is Parents[1].
	repo.addEdgeForTest(dev0, dev1)
	repo.addEdgeForTest(rel1, dev1)
	repo.addEdgeForTest(dev1, dev2)

	repo.addTagForTest(tag100, "v1.0.0")
	repo.addTagForTest(tag101, "v1.0.1")
	// Retired per-release branch refs directly on the tagged leaves themselves.
	repo.markBranchHeadForTest(tag100)
	repo.markBranchHeadForTest(tag101)
	repo.markBranchHeadForTest(rel2)
	repo.markBranchHeadForTest(dev2)

	opts := AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurFixed: true, ResolveTagSpurMaxLength: 5}

	tests := []struct {
		name     string
		se       *SeparatedEvents
		expected []SHA1
	}{
		{
			name: "Retired branch refs on leaves resolve, rel2 is blocked, upward Parents[1] merge into dev is not blocked",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag100)},
				Fixed:      []string{encodeSHA1(tag101)},
			},
			expected: []SHA1{rel0, tag100, rel1, spurMerge, dev1, dev2},
		},
		{
			name: "Merge commit on spur follows Parents[0] to rel1 rather than Parents[1] prFix",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(tag101)},
			},
			expected: []SHA1{rel1, spurMerge, tag101, rel2, untagged, dev1, dev2},
		},
		{
			name: "Untagged dead-end leaf is not resolved",
			se: &SeparatedEvents{
				Introduced: []string{encodeSHA1(untagged)},
			},
			expected: []SHA1{untagged},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits, _ := repo.Affected(t.Context(), tt.se, opts)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_ResolveTagSpur_MultiBranch() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAffected_ResolveTagSpur_LinearHistory(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	// main0 -> main1 -> tag0 [v1.0.0]

	main0, main1, tag0 := decodeSHA1("b0"), decodeSHA1("b1"), decodeSHA1("10")
	repo.addEdgeForTest(main0, main1)
	repo.addEdgeForTest(main1, tag0)
	repo.addTagForTest(tag0, "v1.0.0")

	gotCommits, _ := repo.Affected(t.Context(), &SeparatedEvents{
		Introduced: []string{encodeSHA1(tag0)},
	}, AffectedWalkOptions{ResolveTagSpurIntroduced: true, ResolveTagSpurMaxLength: 5})

	got := make([]SHA1, 0, len(gotCommits))
	for _, c := range gotCommits {
		got = append(got, c.Hash)
	}

	if diff := cmp.Diff([]SHA1{tag0}, got, cmpSHA1Opts...); diff != "" {
		t.Errorf("TestAffected_ResolveTagSpur_LinearHistory() mismatch (-want +got):\n%s", diff)
	}
}

func TestAffected_ResolveTagSpur_Cherrypick(t *testing.T) {
	repo := NewRepository("git://test-repo.git")

	// Graph: (Parent -> Child)
	//            -> tag0 [v1.0.0]     -> tag1 [v1.0.1]
	//           /                    /
	// main0 ---+-------> main1 -----+-------> main2 [branchHead]
	//
	// other0 ----------> other1 ------------> other2 [branchHead]
	// (main0 & other0 share PatchID; main2 & other2 share PatchID)

	main0, main1, main2 := decodeSHA1("b0"), decodeSHA1("b1"), decodeSHA1("b2")
	tag0, tag1 := decodeSHA1("10"), decodeSHA1("11")
	other0, other1, other2 := decodeSHA1("20"), decodeSHA1("21"), decodeSHA1("22")

	repo.addEdgeForTest(main0, main1)
	repo.addEdgeForTest(main1, main2)
	repo.addEdgeForTest(main0, tag0)
	repo.addEdgeForTest(main1, tag1)
	repo.addEdgeForTest(other0, other1)
	repo.addEdgeForTest(other1, other2)
	repo.addTagForTest(tag0, "v1.0.0")
	repo.addTagForTest(tag1, "v1.0.1")
	repo.markBranchHeadForTest(main2)
	repo.markBranchHeadForTest(other2)

	pidIntroAnchor := decodeSHA1("9001")
	pidFixAnchor := decodeSHA1("9002")
	repo.updatePatchID(main0, pidIntroAnchor)
	repo.updatePatchID(other0, pidIntroAnchor)
	repo.updatePatchID(main2, pidFixAnchor)
	repo.updatePatchID(other2, pidFixAnchor)

	gotCommits, cp := repo.Affected(t.Context(), &SeparatedEvents{
		Introduced: []string{encodeSHA1(tag0)},
		Fixed:      []string{encodeSHA1(tag1)},
	}, AffectedWalkOptions{
		CherrypickIntroduced:     true,
		CherrypickFixed:          true,
		ResolveTagSpurIntroduced: true,
		ResolveTagSpurFixed:      true,
	})

	got := make([]SHA1, 0, len(gotCommits))
	for _, c := range gotCommits {
		got = append(got, c.Hash)
	}

	if diff := cmp.Diff([]SHA1{main0, tag0, main1}, got, cmpSHA1Opts...); diff != "" {
		t.Errorf("TestAffected_ResolveTagSpur_Cherrypick() mismatch (-want +got):\n%s", diff)
	}
	if len(cp.Introduced) != 0 || len(cp.Fixed) != 0 {
		t.Errorf("expected no CherryPickedEvents from synthetic anchors, got intro=%v fixed=%v", cp.Introduced, cp.Fixed)
	}
}
