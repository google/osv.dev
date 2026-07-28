// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"slices"
	"testing"
)

func TestParseBreakdownPrefixes_BraceExpansion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected []KeyShard
	}{
		{
			name:  "basic_prefixes",
			input: "ALSA-,BIT-,CVE-",
			expected: []KeyShard{
				{Start: "", End: "ALSA-"},
				{Start: "ALSA-", End: "BIT-"},
				{Start: "BIT-", End: "CVE-"},
				{Start: "CVE-", End: ""},
			},
		},
		{
			name:  "alphabetical_sequence_expansion",
			input: "ALSA-,CGA-{a..c}",
			expected: []KeyShard{
				{Start: "", End: "ALSA-"},
				{Start: "ALSA-", End: "CGA-a"},
				{Start: "CGA-a", End: "CGA-b"},
				{Start: "CGA-b", End: "CGA-c"},
				{Start: "CGA-c", End: ""},
			},
		},
		{
			name:  "numeric_sequence_expansion",
			input: "CGA-{0..2}",
			expected: []KeyShard{
				{Start: "", End: "CGA-0"},
				{Start: "CGA-0", End: "CGA-1"},
				{Start: "CGA-1", End: "CGA-2"},
				{Start: "CGA-2", End: ""},
			},
		},
		{
			name:  "comma_list_brace_expansion",
			input: "ALSA-,CGA-{a,b,c}",
			expected: []KeyShard{
				{Start: "", End: "ALSA-"},
				{Start: "ALSA-", End: "CGA-a"},
				{Start: "CGA-a", End: "CGA-b"},
				{Start: "CGA-b", End: "CGA-c"},
				{Start: "CGA-c", End: ""},
			},
		},
		{
			name:  "multiple_brace_ranges",
			input: "ALSA-,CGA-{a..b},CGA-{0..1}",
			expected: []KeyShard{
				{Start: "", End: "ALSA-"},
				{Start: "ALSA-", End: "CGA-0"},
				{Start: "CGA-0", End: "CGA-1"},
				{Start: "CGA-1", End: "CGA-a"},
				{Start: "CGA-a", End: "CGA-b"},
				{Start: "CGA-b", End: ""},
			},
		},
		{
			name:     "empty_input",
			input:    "",
			expected: []KeyShard{{Start: "", End: ""}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseBreakdownPrefixes(tc.input)
			if !slices.Equal(got, tc.expected) {
				t.Errorf("ParseBreakdownPrefixes(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}
