package main

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// A very simple test repository with 3 commits and 2 tags.
func setupTestRepo(t *testing.T) string {
	t.Helper()
	repoPath := t.TempDir()

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repoPath
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\nOutput: %s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test Name")

	// Commit 1
	err := os.WriteFile(filepath.Join(repoPath, "file1"), []byte("1"), 0600)
	if err != nil {
		t.Fatalf("failed to write file1 for git repo setup: %v", err)
	}
	runGit("add", "file1")
	runGit("commit", "-m", "commit 1")

	// Commit 2 + Tag
	err = os.WriteFile(filepath.Join(repoPath, "file2"), []byte("2"), 0600)
	if err != nil {
		t.Fatalf("failed to write file2 for git repo setup: %v", err)
	}
	runGit("add", "file2")
	runGit("commit", "-m", "commit 2")
	runGit("tag", "v1.0.0")

	// Commit 3 + Tag
	err = os.WriteFile(filepath.Join(repoPath, "file3"), []byte("3"), 0600)
	if err != nil {
		t.Fatalf("failed to write file3 for git repo setup: %v", err)
	}
	runGit("add", "file3")
	runGit("commit", "-m", "commit 3")
	runGit("tag", "v1.1.0")

	return repoPath
}

func TestBuildCommitGraph(t *testing.T) {
	repoPath := setupTestRepo(t)
	r := NewRepository(repoPath)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

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

	// 2 tags + main branch
	if len(r.refToCommit) != 3 {
		t.Errorf("expected 3 refs, got %d", len(r.refToCommit))
	}
}

func TestCalculatePatchIDs(t *testing.T) {
	repoPath := setupTestRepo(t)
	r := NewRepository(repoPath)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

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
	repoPath := setupTestRepo(t)
	ctx := context.WithValue(t.Context(), urlKey, "test-url")

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
	repo := NewRepository("/repo")

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
			expected: []SHA1{h1, h3},
		},
		{
			name:     "No expansion for commit without cherry-pick",
			input:    []int{idx2},
			expected: []SHA1{h2},
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
		name         string
		introduced   []SHA1
		fixed        []SHA1
		lastAffected []SHA1
		expected     []SHA1
	}{
		{
			name:       "Linear: A introduced, B fixed",
			introduced: []SHA1{hA},
			fixed:      []SHA1{hB},
			expected:   []SHA1{hA},
		},
		{
			name:       "Branch propagation: A introduced, C fixed",
			introduced: []SHA1{hA},
			fixed:      []SHA1{hC},
			expected:   []SHA1{hA, hB, hH},
		},
		{
			name:       "Re-introduced: (A,C) introduced, (B,D,G) fixed",
			introduced: []SHA1{hA, hC},
			fixed:      []SHA1{hB, hD, hG},
			expected:   []SHA1{hA, hC, hF},
		},
		{
			name:       "Merge intro: H introduced, E fixed",
			introduced: []SHA1{hH},
			fixed:      []SHA1{hE},
			expected:   []SHA1{hH, hD},
		},
		{
			name:       "Merge fix: A introduced, H fixed",
			introduced: []SHA1{hA},
			fixed:      []SHA1{hH},
			expected:   []SHA1{hA, hB, hC, hF, hG},
		},
		{
			name:       "Merge intro and fix (different branches): C introduced, H fixed",
			introduced: []SHA1{hC},
			fixed:      []SHA1{hH},
			expected:   []SHA1{hC, hD, hE, hF, hG},
		},
		{
			name:       "Everything affected if no fix",
			introduced: []SHA1{hA},
			expected:   []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert SHA1 to string for the new API
			introStrs := make([]string, len(tt.introduced))
			for i, h := range tt.introduced {
				introStrs[i] = encodeSHA1(h)
			}
			fixedStrs := make([]string, len(tt.fixed))
			for i, h := range tt.fixed {
				fixedStrs[i] = encodeSHA1(h)
			}
			laStrs := make([]string, len(tt.lastAffected))
			for i, h := range tt.lastAffected {
				laStrs[i] = encodeSHA1(h)
			}
			se := &SeparatedEvents{
				Introduced:   introStrs,
				Fixed:        fixedStrs,
				LastAffected: laStrs,
			}
			gotCommits := repo.Affected(t.Context(), se, false, false)

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
		name         string
		introduced   []SHA1
		fixed        []SHA1
		lastAffected []SHA1
		expected     []SHA1
	}{
		{
			name:         "Linear: D introduced, E lastAffected",
			introduced:   []SHA1{hD},
			lastAffected: []SHA1{hE},
			expected:     []SHA1{hD, hE},
		},
		{
			name:         "Branch propagation: A introduced, C lastAffected",
			introduced:   []SHA1{hA},
			lastAffected: []SHA1{hC},
			expected:     []SHA1{hA, hB, hC, hH},
		},
		{
			name:         "Re-introduced: (A,D) introduced, (B,E) lastAffected",
			introduced:   []SHA1{hA, hD},
			lastAffected: []SHA1{hB, hE},
			expected:     []SHA1{hA, hB, hD, hE},
		},
		{
			name:         "Merge intro: H introduced, D lastAffected",
			introduced:   []SHA1{hH},
			lastAffected: []SHA1{hD},
			expected:     []SHA1{hH, hD},
		},
		{
			name:         "Merge lastAffected: A introduced, H lastAffected",
			introduced:   []SHA1{hA},
			lastAffected: []SHA1{hH},
			expected:     []SHA1{hA, hB, hC, hF, hG, hH},
		},
		{
			name:         "Merge intro and lastAffected (different branches): C introduced, H lastAffected",
			introduced:   []SHA1{hC},
			lastAffected: []SHA1{hH},
			expected:     []SHA1{hC, hF, hG},
		},
		{
			name:       "Everything affected if no lastAffected",
			introduced: []SHA1{hA},
			expected:   []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert SHA1 to string for the new API
			introStrs := make([]string, len(tt.introduced))
			for i, h := range tt.introduced {
				introStrs[i] = encodeSHA1(h)
			}
			fixedStrs := make([]string, len(tt.fixed))
			for i, h := range tt.fixed {
				fixedStrs[i] = encodeSHA1(h)
			}
			laStrs := make([]string, len(tt.lastAffected))
			for i, h := range tt.lastAffected {
				laStrs[i] = encodeSHA1(h)
			}
			se := &SeparatedEvents{
				Introduced:   introStrs,
				Fixed:        fixedStrs,
				LastAffected: laStrs,
			}
			gotCommits := repo.Affected(t.Context(), se, false, false)

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
		name         string
		introduced   []SHA1
		fixed        []SHA1
		lastAffected []SHA1
		expected     []SHA1
	}{
		{
			name:         "Branching out: C introduced, G fixed, D lastAffected",
			introduced:   []SHA1{hC},
			fixed:        []SHA1{hG},
			lastAffected: []SHA1{hD},
			expected:     []SHA1{hC, hD, hF},
		},
		{
			name:         "Redundant Blocking: A introduced, B fixed, E lastAffected",
			introduced:   []SHA1{hA},
			fixed:        []SHA1{hB},
			lastAffected: []SHA1{hE},
			expected:     []SHA1{hA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert SHA1 to string for the new API
			introStrs := make([]string, len(tt.introduced))
			for i, h := range tt.introduced {
				introStrs[i] = encodeSHA1(h)
			}
			fixedStrs := make([]string, len(tt.fixed))
			for i, h := range tt.fixed {
				fixedStrs[i] = encodeSHA1(h)
			}
			laStrs := make([]string, len(tt.lastAffected))
			for i, h := range tt.lastAffected {
				laStrs[i] = encodeSHA1(h)
			}
			se := &SeparatedEvents{
				Introduced:   introStrs,
				Fixed:        fixedStrs,
				LastAffected: laStrs,
			}
			gotCommits := repo.Affected(t.Context(), se, false, false)

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
	repo := NewRepository("/repo")

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

	tests := []struct {
		name            string
		introduced      []SHA1
		fixed           []SHA1
		cherrypickIntro bool
		cherrypickFixed bool
		expected        []SHA1
	}{
		{
			name:            "Cherrypick Introduced Only: A introduced, G fixed",
			introduced:      []SHA1{hA},
			fixed:           []SHA1{hG},
			cherrypickIntro: true,
			cherrypickFixed: false,
			expected:        []SHA1{hA, hB, hC, hD, hE, hF},
		},
		{
			name:            "Cherrypick Fixed Only: A introduced, G fixed",
			introduced:      []SHA1{hA},
			fixed:           []SHA1{hG},
			cherrypickIntro: false,
			cherrypickFixed: true,
			expected:        []SHA1{hA, hB},
		},
		{
			name:            "Cherrypick Introduced and Fixed: A introduced, G fixed",
			introduced:      []SHA1{hA},
			fixed:           []SHA1{hG},
			cherrypickIntro: true,
			cherrypickFixed: true,
			expected:        []SHA1{hA, hB, hE, hF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert SHA1 to string for the new API
			introStrs := make([]string, len(tt.introduced))
			for i, h := range tt.introduced {
				introStrs[i] = encodeSHA1(h)
			}
			fixedStrs := make([]string, len(tt.fixed))
			for i, h := range tt.fixed {
				fixedStrs[i] = encodeSHA1(h)
			}

			se := &SeparatedEvents{
				Introduced: introStrs,
				Fixed:      fixedStrs,
			}
			gotCommits := repo.Affected(t.Context(), se, tt.cherrypickIntro, tt.cherrypickFixed)

			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			if diff := cmp.Diff(tt.expected, got, cmpSHA1Opts...); diff != "" {
				t.Errorf("TestAffected_Cherrypick() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLimit(t *testing.T) {
	repo := NewRepository("/repo")

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

	tests := []struct {
		name       string
		introduced []SHA1
		limit      []SHA1
		expected   []SHA1
	}{
		{
			name:       "One branch: A introduced, D limit",
			introduced: []SHA1{hA},
			limit:      []SHA1{hD},
			expected:   []SHA1{hA, hB, hC},
		},
		{
			name:       "Side branch: A introduced, G limit",
			introduced: []SHA1{hA},
			limit:      []SHA1{hG},
			expected:   []SHA1{hA, hB, hF},
		},
		{
			name:       "Two branches: A introduced, (D,G) limit",
			introduced: []SHA1{hA},
			limit:      []SHA1{hD, hG},
			expected:   []SHA1{hA, hB, hC, hF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert SHA1 to string for the new API
			introStrs := make([]string, len(tt.introduced))
			for i, h := range tt.introduced {
				introStrs[i] = encodeSHA1(h)
			}
			limitStrs := make([]string, len(tt.limit))
			for i, h := range tt.limit {
				limitStrs[i] = encodeSHA1(h)
			}

			se := &SeparatedEvents{
				Introduced: introStrs,
				Limit:      limitStrs,
			}
			gotCommits := repo.Limit(t.Context(), se)

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
