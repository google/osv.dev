package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Helper to decode string into SHA1
func decodeSHA1(s string) SHA1 {
	var hash SHA1
	// Pad with zeros because the test strings are shorter than 40 char
	padded := fmt.Sprintf("%040s", s)
	b, err := hex.DecodeString(padded)
	if err != nil {
		panic(err)
	}
	copy(hash[:], b)

	return hash
}

// Helper to encode SHA1 into string (leading 0's removed)
func encodeSHA1(hash SHA1) string {
	// Remove padding zeros for a cleaner results
	str := hex.EncodeToString(hash[:])

	return strings.TrimLeft(str, "0")
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
	repo.commitDetails[h1] = &Commit{Hash: h1, PatchID: p1}
	repo.commitDetails[h2] = &Commit{Hash: h2}
	repo.commitDetails[h3] = &Commit{Hash: h3, PatchID: p1} // h3 has the same patch ID as h1 should be cherry picked

	// Setup patch ID map
	repo.patchIDToCommits[p1] = []SHA1{h1, h3}

	tests := []struct {
		name     string
		input    []SHA1
		expected []SHA1
	}{
		{
			name:     "Expand single commit with cherry-pick",
			input:    []SHA1{h1},
			expected: []SHA1{h1, h3},
		},
		{
			name:     "No expansion for commit without cherry-pick",
			input:    []SHA1{h2},
			expected: []SHA1{h2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repo.expandByCherrypick(tt.input)

			if diff := cmp.Diff(tt.expected, got); diff != "" {
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
	repo.commitGraph[hA] = []SHA1{hB}
	repo.commitGraph[hB] = []SHA1{hC, hH}
	repo.commitGraph[hC] = []SHA1{hD, hF}
	repo.commitGraph[hD] = []SHA1{hE}
	repo.commitGraph[hF] = []SHA1{hG}
	repo.commitGraph[hH] = []SHA1{hD}

	// Setup details
	repo.commitDetails[hA] = &Commit{Hash: hA}
	repo.commitDetails[hB] = &Commit{Hash: hB}
	repo.commitDetails[hC] = &Commit{Hash: hC}
	repo.commitDetails[hD] = &Commit{Hash: hD}
	repo.commitDetails[hE] = &Commit{Hash: hE}
	repo.commitDetails[hF] = &Commit{Hash: hF}
	repo.commitDetails[hG] = &Commit{Hash: hG}
	repo.commitDetails[hH] = &Commit{Hash: hH}

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
			name:       "Branch propagation: A introduced, D fixed",
			introduced: []SHA1{hA},
			fixed:      []SHA1{hD},
			expected:   []SHA1{hA, hB, hC, hF, hG, hH},
		},
		{
			name:       "Diverged before introduce: C introduced, E fixed",
			introduced: []SHA1{hC},
			fixed:      []SHA1{hE},
			expected:   []SHA1{hC, hD, hF, hG},
		},
		{
			name:       "Two sets: (A,C) introduced, (B,D,G) fixed",
			introduced: []SHA1{hA, hC},
			fixed:      []SHA1{hB, hD, hG},
			expected:   []SHA1{hA, hC, hF},
		},
		{
			name:       "Merge fix: A introduced, H fixed",
			introduced: []SHA1{hA},
			fixed:      []SHA1{hH},
			expected:   []SHA1{hA, hB, hC, hF, hG},
		},
		{
			name:       "Everything affected if no fix",
			introduced: []SHA1{hA},
			expected:   []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits := repo.Affected(tt.introduced, tt.fixed, tt.lastAffected, false)
			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			// Sort got and expected for comparison
			sort.Slice(got, func(i, j int) bool {
				return string(got[i][:]) < string(got[j][:])
			})
			sort.Slice(tt.expected, func(i, j int) bool {
				return string(tt.expected[i][:]) < string(tt.expected[j][:])
			})

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				// Turn them back into strings so it's easier to read
				gotStr := make([]string, len(got))
				for i, c := range got {
					gotStr[i] = encodeSHA1(c)
				}
				expectedStr := make([]string, len(tt.expected))
				for i, c := range tt.expected {
					expectedStr[i] = encodeSHA1(c)
				}

				t.Errorf("TestAffected_Introduced_Fixed() mismatch\nGot: %v\nExpected: %v", gotStr, expectedStr)
			}
		})
	}
}

func TestAffected_Introduced_LastAffected(t *testing.T) {
	repo := NewRepository("/repo")

	// Graph: (Parent -> Child)
	// A -> B -> C -> D -> E -> F
	//      \ 	     /
	//       ->  G ->  H

	hA := decodeSHA1("aaaa")
	hB := decodeSHA1("bbbb")
	hC := decodeSHA1("cccc")
	hD := decodeSHA1("dddd")
	hE := decodeSHA1("eeee")
	hF := decodeSHA1("ffff")
	hG := decodeSHA1("abab")
	hH := decodeSHA1("acac")

	// Setup graph (Parent -> Children)
	repo.commitGraph[hA] = []SHA1{hB}
	repo.commitGraph[hB] = []SHA1{hC, hG}
	repo.commitGraph[hC] = []SHA1{hD}
	repo.commitGraph[hD] = []SHA1{hE}
	repo.commitGraph[hE] = []SHA1{hF}
	repo.commitGraph[hG] = []SHA1{hD, hH}

	// Setup details
	repo.commitDetails[hA] = &Commit{Hash: hA}
	repo.commitDetails[hB] = &Commit{Hash: hB}
	repo.commitDetails[hC] = &Commit{Hash: hC}
	repo.commitDetails[hD] = &Commit{Hash: hD}
	repo.commitDetails[hE] = &Commit{Hash: hE}
	repo.commitDetails[hF] = &Commit{Hash: hF}
	repo.commitDetails[hG] = &Commit{Hash: hG}
	repo.commitDetails[hH] = &Commit{Hash: hH}

	tests := []struct {
		name         string
		introduced   []SHA1
		fixed        []SHA1
		lastAffected []SHA1
		expected     []SHA1
	}{
		{
			name:         "Linear: E introduced, F lastAffected",
			introduced:   []SHA1{hE},
			lastAffected: []SHA1{hF},
			expected:     []SHA1{hE, hF},
		},
		{
			name:         "Branch propagation: A introduced, D lastAffected",
			introduced:   []SHA1{hA},
			lastAffected: []SHA1{hD},
			expected:     []SHA1{hA, hB, hC, hD, hG, hH},
		},
		{
			name:         "Diverged before introduce: C introduced, E lastAffected",
			introduced:   []SHA1{hC},
			lastAffected: []SHA1{hE},
			expected:     []SHA1{hC, hD, hE},
		},
		{
			name:         "Two sets: (C,E) introduced, (D,F) lastAffected",
			introduced:   []SHA1{hC, hE},
			lastAffected: []SHA1{hD, hF},
			expected:     []SHA1{hC, hD, hE, hF},
		},
		{
			name:       "Everything affected if no lastAffected",
			introduced: []SHA1{hA},
			expected:   []SHA1{hA, hB, hC, hD, hE, hF, hG, hH},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommits := repo.Affected(tt.introduced, tt.fixed, tt.lastAffected, false)
			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			// Sort got and expected for comparison
			sort.Slice(got, func(i, j int) bool {
				return string(got[i][:]) < string(got[j][:])
			})
			sort.Slice(tt.expected, func(i, j int) bool {
				return string(tt.expected[i][:]) < string(tt.expected[j][:])
			})

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				// Turn them back into strings so it's easier to read
				gotStr := make([]string, len(got))
				for i, c := range got {
					gotStr[i] = encodeSHA1(c)
				}
				expectedStr := make([]string, len(tt.expected))
				for i, c := range tt.expected {
					expectedStr[i] = encodeSHA1(c)
				}

				t.Errorf("TestAffected_Introduced_LastAffected() mismatch\nGot: %v\nExpected: %v", gotStr, expectedStr)
			}
		})
	}
}

func TestBetween(t *testing.T) {
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
	repo.commitGraph[hA] = []SHA1{hB}
	repo.commitGraph[hB] = []SHA1{hC, hF}
	repo.commitGraph[hC] = []SHA1{hD}
	repo.commitGraph[hD] = []SHA1{hE}
	repo.commitGraph[hF] = []SHA1{hG}
	repo.commitGraph[hG] = []SHA1{hH}

	// Setup details
	repo.commitDetails[hA] = &Commit{Hash: hA}
	repo.commitDetails[hB] = &Commit{Hash: hB, Parents: []SHA1{hA}}
	repo.commitDetails[hC] = &Commit{Hash: hC, Parents: []SHA1{hB}}
	repo.commitDetails[hD] = &Commit{Hash: hD, Parents: []SHA1{hC}}
	repo.commitDetails[hE] = &Commit{Hash: hE, Parents: []SHA1{hD}}
	repo.commitDetails[hF] = &Commit{Hash: hF, Parents: []SHA1{hB}}
	repo.commitDetails[hG] = &Commit{Hash: hG, Parents: []SHA1{hF}}
	repo.commitDetails[hH] = &Commit{Hash: hH, Parents: []SHA1{hG}}

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
			gotCommits := repo.Between(tt.introduced, tt.limit)
			var got []SHA1
			for _, c := range gotCommits {
				got = append(got, c.Hash)
			}

			// Sort got and expected for comparison
			sort.Slice(got, func(i, j int) bool {
				return string(got[i][:]) < string(got[j][:])
			})
			sort.Slice(tt.expected, func(i, j int) bool {
				return string(tt.expected[i][:]) < string(tt.expected[j][:])
			})

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				// Turn them back into strings so it's easier to read
				gotStr := make([]string, len(got))
				for i, c := range got {
					gotStr[i] = encodeSHA1(c)
				}
				expectedStr := make([]string, len(tt.expected))
				for i, c := range tt.expected {
					expectedStr[i] = encodeSHA1(c)
				}

				t.Errorf("TestBetween() mismatch\nGot: %v\nExpected: %v", gotStr, expectedStr)
			}
		})
	}
}
