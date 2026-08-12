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

package sharding_test

import (
	"slices"
	"testing"

	"github.com/google/osv.dev/go/internal/sharding"
)

func TestExpandBreakdownPrefixes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty_input",
			input:    "",
			expected: nil,
		},
		{
			name:     "basic_prefixes",
			input:    "ALSA-,BIT-,CVE-",
			expected: []string{"ALSA-", "BIT-", "CVE-"},
		},
		{
			name:     "sequence_expansion",
			input:    "ALSA-,CGA-{a..c}",
			expected: []string{"ALSA-", "CGA-a", "CGA-b", "CGA-c"},
		},
		{
			name:     "numeric_sequence_expansion",
			input:    "CGA-{0..2}",
			expected: []string{"CGA-0", "CGA-1", "CGA-2"},
		},
		{
			name:     "comma_list_brace_expansion",
			input:    "ALSA-,CGA-{a,b,c}",
			expected: []string{"ALSA-", "CGA-a", "CGA-b", "CGA-c"},
		},
		{
			name:     "nested_brace_expansion",
			input:    "CGA-{{0..9},{a..z}}",
			expected: []string{"CGA-0", "CGA-1", "CGA-2", "CGA-3", "CGA-4", "CGA-5", "CGA-6", "CGA-7", "CGA-8", "CGA-9", "CGA-a", "CGA-b", "CGA-c", "CGA-d", "CGA-e", "CGA-f", "CGA-g", "CGA-h", "CGA-i", "CGA-j", "CGA-k", "CGA-l", "CGA-m", "CGA-n", "CGA-o", "CGA-p", "CGA-q", "CGA-r", "CGA-s", "CGA-t", "CGA-u", "CGA-v", "CGA-w", "CGA-x", "CGA-y", "CGA-z"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sharding.ExpandBreakdownPrefixes(tc.input)
			if !slices.Equal(got, tc.expected) {
				t.Errorf("ExpandBreakdownPrefixes(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseBreakdownPrefixes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected []sharding.KeyShard
	}{
		{
			name:     "empty_input",
			input:    "",
			expected: []sharding.KeyShard{{Start: "", End: ""}},
		},
		{
			name:  "alphabetical_sequence_expansion",
			input: "ALSA-,CGA-{a..c}",
			expected: []sharding.KeyShard{
				{Start: "", End: "ALSA-"},
				{Start: "ALSA-", End: "CGA-a"},
				{Start: "CGA-a", End: "CGA-b"},
				{Start: "CGA-b", End: "CGA-c"},
				{Start: "CGA-c", End: ""},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sharding.ParseBreakdownPrefixes(tc.input)
			if !slices.Equal(got, tc.expected) {
				t.Errorf("ParseBreakdownPrefixes(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}
