// Copyright 2025 Google LLC
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
	"context"
	"encoding/json"
	"slices"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/osv/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestComputeUpstream(t *testing.T) {
	vulns := map[string][]string{
		"CVE-1": {},
		"CVE-2": {"CVE-1"},
		"CVE-3": {"CVE-1", "CVE-2"},
	}

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Basic transitive",
			input:    []string{"CVE-1", "CVE-2"},
			expected: []string{"CVE-1", "CVE-2"},
		},
		{
			name:     "Basic transitive from CVE-3",
			input:    []string{"CVE-1", "CVE-2"}, // CVE-3's direct upstreams
			expected: []string{"CVE-1", "CVE-2"},
		},
		{
			name: "Example complex",
			input: []string{
				"CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103",
				"CVE-2024-53141", "CVE-2024-53164", "UBUNTU-CVE-2023-21400",
				"UBUNTU-CVE-2024-40967", "UBUNTU-CVE-2024-53103",
				"UBUNTU-CVE-2024-53141", "UBUNTU-CVE-2024-53164",
			},
			expected: []string{
				"CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103", "CVE-2024-53141",
				"CVE-2024-53164", "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2024-40967",
				"UBUNTU-CVE-2024-53103", "UBUNTU-CVE-2024-53141",
				"UBUNTU-CVE-2024-53164",
			},
		},
		{
			name:     "Incomplete upstream",
			input:    []string{"VULN-3"}, // VULN-4's direct upstream
			expected: []string{"VULN-1", "VULN-3"},
		},
	}

	// Add data for complex example and incomplete upstream
	vulns["UBUNTU-CVE-2023-21400"] = []string{"CVE-2023-21400"}
	vulns["VULN-1"] = []string{}
	vulns["VULN-2"] = []string{"VULN-1"}
	vulns["VULN-3"] = []string{"VULN-1"}
	vulns["VULN-4"] = []string{"VULN-3"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sort expected for comparison, as computeUpstream returns sorted list
			slices.Sort(tt.expected)
			actual := computeUpstream(tt.input, vulns)
			if !slices.Equal(actual, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}

func TestComputeUpstreamGroups(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)

	// Setup data
	vulns := []*models.Vulnerability{
		{Key: datastore.NameKey("Vulnerability", "CVE-1", nil), UpstreamRaw: []string{}},
		{Key: datastore.NameKey("Vulnerability", "CVE-2", nil), UpstreamRaw: []string{"CVE-1"}},
		{Key: datastore.NameKey("Vulnerability", "CVE-3", nil), UpstreamRaw: []string{"CVE-1", "CVE-2"}},
		{Key: datastore.NameKey("Vulnerability", "CVE-2023-21400", nil), UpstreamRaw: []string{}},
		{Key: datastore.NameKey("Vulnerability", "UBUNTU-CVE-2023-21400", nil), UpstreamRaw: []string{"CVE-2023-21400"}},
		{Key: datastore.NameKey("Vulnerability", "UBUNTU-CVE-2023-4004", nil), UpstreamRaw: []string{"CVE-2023-4004"}},
		{Key: datastore.NameKey("Vulnerability", "UBUNTU-CVE-2023-4015", nil), UpstreamRaw: []string{"CVE-2023-4015"}},
		{
			Key: datastore.NameKey("Vulnerability", "USN-6315-1", nil),
			UpstreamRaw: []string{
				"CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400",
				"CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776",
				"CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
				"UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2023-20593",
				"UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-3609",
				"UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
				"UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
				"UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015",
			},
		},
		// Add other USNs if needed, but only USN-7234-3 is used in tests
		{
			Key: datastore.NameKey("Vulnerability", "USN-7234-3", nil),
			UpstreamRaw: []string{
				"CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103",
				"CVE-2024-53141", "CVE-2024-53164", "UBUNTU-CVE-2023-21400",
				"UBUNTU-CVE-2024-40967", "UBUNTU-CVE-2024-53103",
				"UBUNTU-CVE-2024-53141", "UBUNTU-CVE-2024-53164",
			},
		},
	}
	for _, v := range vulns {
		if _, err := dsClient.Put(ctx, v.Key, v); err != nil {
			t.Fatalf("failed to put vuln: %v", err)
		}
	}

	ch := make(chan Update, 100)
	if err := ComputeUpstreamGroups(ctx, dsClient, ch); err != nil {
		t.Fatalf("ComputeUpstreamGroups failed: %v", err)
	}
	close(ch)

	//nolint:revive // Drain channel
	for range ch {
	}

	t.Run("test_upstream_group_basic", func(t *testing.T) {
		// CVE-1-> CVE-2 -> CVE-3
		// Upstream of CVE-3 is CVE-2 & CVE-1
		var groups []models.UpstreamGroup
		query := datastore.NewQuery("UpstreamGroup").FilterField("db_id", "=", "CVE-3")
		if _, err := dsClient.GetAll(ctx, query, &groups); err != nil {
			t.Fatalf("failed to get UpstreamGroup CVE-3: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 UpstreamGroup for CVE-3, got %d", len(groups))
		}
		expected := []string{"CVE-1", "CVE-2"}
		if !slices.Equal(groups[0].UpstreamIDs, expected) {
			t.Errorf("expected %v, got %v", expected, groups[0].UpstreamIDs)
		}
	})

	t.Run("test_upstream_group_complex", func(t *testing.T) {
		// Test real world case with multiple levels
		var groups []models.UpstreamGroup
		query := datastore.NewQuery("UpstreamGroup").FilterField("db_id", "=", "USN-7234-3")
		if _, err := dsClient.GetAll(ctx, query, &groups); err != nil {
			t.Fatalf("failed to get UpstreamGroup USN-7234-3: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 UpstreamGroup for USN-7234-3, got %d", len(groups))
		}
		expected := []string{
			"CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103", "CVE-2024-53141",
			"CVE-2024-53164", "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2024-40967",
			"UBUNTU-CVE-2024-53103", "UBUNTU-CVE-2024-53141",
			"UBUNTU-CVE-2024-53164",
		}
		slices.Sort(expected) // Go implementation sorts, Python test seems to expect sorted too based on test_upstream_group_complex
		if !slices.Equal(groups[0].UpstreamIDs, expected) {
			t.Errorf("expected %v, got %v", expected, groups[0].UpstreamIDs)
		}
	})

	t.Run("test_upstream_hierarchy_computation", func(t *testing.T) {
		var groups []models.UpstreamGroup
		query := datastore.NewQuery("UpstreamGroup").FilterField("db_id", "=", "CVE-3")
		if _, err := dsClient.GetAll(ctx, query, &groups); err != nil {
			t.Fatalf("failed to get UpstreamGroup CVE-3: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 UpstreamGroup for CVE-3, got %d", len(groups))
		}
		var hierarchy map[string][]string
		if err := json.Unmarshal(groups[0].UpstreamHierarchy, &hierarchy); err != nil {
			t.Fatalf("failed to unmarshal hierarchy: %v", err)
		}
		expected := map[string][]string{
			"CVE-3": {"CVE-2"},
			"CVE-2": {"CVE-1"},
		}
		if len(hierarchy) != len(expected) {
			t.Errorf("expected %v, got %v", expected, hierarchy)
		}
		for k, v := range expected {
			if !slices.Equal(hierarchy[k], v) {
				t.Errorf("for key %s, expected %v, got %v", k, v, hierarchy[k])
			}
		}
	})

	t.Run("test_upstream_hierarchy_computation_complex", func(t *testing.T) {
		var groups []models.UpstreamGroup
		query := datastore.NewQuery("UpstreamGroup").FilterField("db_id", "=", "USN-7234-3")
		if _, err := dsClient.GetAll(ctx, query, &groups); err != nil {
			t.Fatalf("failed to get UpstreamGroup USN-7234-3: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 UpstreamGroup for USN-7234-3, got %d", len(groups))
		}
		var hierarchy map[string][]string
		if err := json.Unmarshal(groups[0].UpstreamHierarchy, &hierarchy); err != nil {
			t.Fatalf("failed to unmarshal hierarchy: %v", err)
		}
		expected := map[string][]string{
			"USN-7234-3": {
				"CVE-2024-40967", "CVE-2024-53103", "CVE-2024-53141",
				"CVE-2024-53164", "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2024-40967",
				"UBUNTU-CVE-2024-53103", "UBUNTU-CVE-2024-53141",
				"UBUNTU-CVE-2024-53164",
			},
			"UBUNTU-CVE-2023-21400": {"CVE-2023-21400"},
		}
		// Sort expected values for comparison
		for k := range expected {
			slices.Sort(expected[k])
		}
		if len(hierarchy) != len(expected) {
			t.Errorf("expected length %d, got %d", len(expected), len(hierarchy))
		}
		for k, v := range expected {
			if !slices.Equal(hierarchy[k], v) {
				t.Errorf("for key %s, expected %v, got %v", k, v, hierarchy[k])
			}
		}
	})
}
