package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/osv/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestComputeRelated(t *testing.T) {
	tests := []struct {
		name   string
		groups map[string][]string
		want   map[string][]string
	}{
		{
			name:   "Unrelated groups",
			groups: map[string][]string{"A": {"B"}, "C": {"D"}},
			want:   map[string][]string{"A": {"B"}, "B": {"A"}, "C": {"D"}, "D": {"C"}},
		},
		{
			name:   "Related groups",
			groups: map[string][]string{"A": {"B", "C"}, "B": {"A"}},
			want:   map[string][]string{"A": {"B", "C"}, "B": {"A"}, "C": {"A"}},
		},
		{
			name:   "Already computed",
			groups: map[string][]string{"A": {"B"}, "B": {"A"}},
			want:   map[string][]string{"A": {"B"}, "B": {"A"}},
		},
		{
			name:   "Circular",
			groups: map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"A"}},
			want:   map[string][]string{"A": {"B", "C"}, "B": {"A", "C"}, "C": {"A", "B"}},
		},
		{
			name:   "Empty",
			groups: map[string][]string{},
			want:   map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeRelated(tt.groups, map[string]struct{}{})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("computeRelated() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestComputeRelatedGroups(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)

	// Setup Datastore
	vulns := []*models.Vulnerability{
		{
			Key:        datastore.NameKey("Vulnerability", "A", nil),
			RelatedRaw: []string{"B"},
			Modified:   time.Now().UTC(),
		},
		{
			Key:        datastore.NameKey("Vulnerability", "B", nil),
			RelatedRaw: []string{"A"},
			Modified:   time.Now().UTC(),
		},
		{
			Key:        datastore.NameKey("Vulnerability", "C", nil),
			RelatedRaw: []string{"A", "D"},
			Modified:   time.Now().UTC(),
		},
		{
			Key:         datastore.NameKey("Vulnerability", "D", nil),
			RelatedRaw:  []string{"E"}, // Withdrawn, should be ignored
			Modified:    time.Now().UTC(),
			IsWithdrawn: true,
		},
	}
	keys := make([]*datastore.Key, len(vulns))
	for i, v := range vulns {
		keys[i] = v.Key
	}

	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	ch := make(chan Update, 100)
	if err := ComputeRelatedGroups(ctx, dsClient, ch); err != nil {
		t.Fatalf("ComputeRelatedGroups failed: %v", err)
	}
	close(ch)

	// Check results
	var groups []models.RelatedGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("RelatedGroup"), &groups); err != nil {
		t.Fatalf("failed to get related groups: %v", err)
	}

	expected := map[string][]string{
		"A": {"B", "C"},
		"B": {"A"},
		"C": {"A", "D"},
		"D": {"C", "E"},
	}

	got := make(map[string][]string)
	for _, g := range groups {
		slices.Sort(g.RelatedIDs)
		got[g.Key.Name] = g.RelatedIDs
	}

	if diff := cmp.Diff(expected, got); diff != "" {
		t.Errorf("RelatedGroups mismatch (-want +got):\n%s", diff)
	}
}
