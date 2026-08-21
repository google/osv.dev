package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestRelationsStore_GetAliases(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	now := time.Now().Truncate(time.Second) // Datastore may truncate fractional seconds

	aliasGroups := []AliasGroup{
		{
			VulnIDs:  []string{"VULN-A", "VULN-B", "VULN-C"},
			Modified: now,
		},
		{
			VulnIDs:  []string{"VULN-D", "VULN-E"},
			Modified: now,
		},
	}

	keys := []*datastore.Key{
		datastore.IncompleteKey("AliasGroup", nil),
		datastore.IncompleteKey("AliasGroup", nil),
	}

	if _, err := dsClient.PutMulti(ctx, keys, aliasGroups); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		wantAliases []string
		wantErr     error
	}{
		{
			name:        "Find aliases for VULN-A",
			id:          "VULN-A",
			wantAliases: []string{"VULN-B", "VULN-C"},
			wantErr:     nil,
		},
		{
			name:        "Find aliases for VULN-B",
			id:          "VULN-B",
			wantAliases: []string{"VULN-A", "VULN-C"},
			wantErr:     nil,
		},
		{
			name:        "Find aliases for VULN-D",
			id:          "VULN-D",
			wantAliases: []string{"VULN-E"},
			wantErr:     nil,
		},
		{
			name:        "Not found",
			id:          "VULN-UNKNOWN",
			wantAliases: nil,
			wantErr:     models.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := store.GetAliases(ctx, tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetAliases() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tt.wantAliases, res.Aliases); diff != "" {
				t.Errorf("GetAliases() aliases mismatch (-want +got):\n%s", diff)
			}

			if !res.Modified.Equal(now) {
				t.Errorf("GetAliases() modified mismatch, got %v, want %v", res.Modified, now)
			}
		})
	}
}

func TestRelationsStore_GetAliases_MultipleGroups(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	now := time.Now()

	// VULN-A belongs to two groups (invalid state)
	aliasGroups := []AliasGroup{
		{
			VulnIDs:  []string{"VULN-A", "VULN-B"},
			Modified: now,
		},
		{
			VulnIDs:  []string{"VULN-A", "VULN-C"},
			Modified: now,
		},
	}

	keys := []*datastore.Key{
		datastore.IncompleteKey("AliasGroup", nil),
		datastore.IncompleteKey("AliasGroup", nil),
	}

	if _, err := dsClient.PutMulti(ctx, keys, aliasGroups); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	_, err := store.GetAliases(ctx, "VULN-A")
	if err == nil || err.Error() != "id belongs to multiple aliases" {
		t.Errorf("Expected 'id belongs to multiple aliases' error, got %v", err)
	}
}

func TestRelationsStore_GetRelated(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	now := time.Now().Truncate(time.Second)

	relatedGroup := RelatedGroup{
		RelatedIDs: []string{"RELATED-1", "RELATED-2"},
		Modified:   now,
	}

	key := datastore.NameKey("RelatedGroup", "VULN-A", nil)

	if _, err := dsClient.Put(ctx, key, &relatedGroup); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		wantRelated []string
		wantErr     error
	}{
		{
			name:        "Found",
			id:          "VULN-A",
			wantRelated: []string{"RELATED-1", "RELATED-2"},
			wantErr:     nil,
		},
		{
			name:        "Not found",
			id:          "VULN-UNKNOWN",
			wantRelated: nil,
			wantErr:     models.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := store.GetRelated(ctx, tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetRelated() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tt.wantRelated, res.Related); diff != "" {
				t.Errorf("GetRelated() related mismatch (-want +got):\n%s", diff)
			}

			if !res.Modified.Equal(now) {
				t.Errorf("GetRelated() modified mismatch, got %v, want %v", res.Modified, now)
			}
		})
	}
}

func TestRelationsStore_GetUpstream(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	now := time.Now().Truncate(time.Second)

	upstreamGroup := UpstreamGroup{
		VulnID:      "VULN-A",
		UpstreamIDs: []string{"UPSTREAM-1", "UPSTREAM-2"},
		Modified:    now,
	}

	key := datastore.IncompleteKey("UpstreamGroup", nil)

	if _, err := dsClient.Put(ctx, key, &upstreamGroup); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	tests := []struct {
		name         string
		id           string
		wantUpstream []string
		wantErr      error
	}{
		{
			name:         "Found",
			id:           "VULN-A",
			wantUpstream: []string{"UPSTREAM-1", "UPSTREAM-2"},
			wantErr:      nil,
		},
		{
			name:         "Not found",
			id:           "VULN-UNKNOWN",
			wantUpstream: nil,
			wantErr:      models.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := store.GetUpstream(ctx, tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetUpstream() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tt.wantUpstream, res.Upstream); diff != "" {
				t.Errorf("GetUpstream() upstream mismatch (-want +got):\n%s", diff)
			}

			if !res.Modified.Equal(now) {
				t.Errorf("GetUpstream() modified mismatch, got %v, want %v", res.Modified, now)
			}
		})
	}
}

func TestComputeUpstreamHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		targetID     string
		rawHierarchy map[string][]string
		want         *models.Hierarchy
		wantErr      error
	}{
		{
			name:         "Empty",
			targetID:     "VULN-1",
			rawHierarchy: nil,
			want:         nil,
			wantErr:      models.ErrNotFound,
		},
		{
			name:     "Simple hierarchy",
			targetID: "VULN-1",
			rawHierarchy: map[string][]string{
				"VULN-1": {"UPSTREAM-1"},
			},
			want: &models.Hierarchy{
				Roots: []string{"UPSTREAM-1"},
				Graph: map[string][]string{
					"UPSTREAM-1": {"VULN-1"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Multi-level multi-root hierarchy",
			targetID: "VULN-1",
			rawHierarchy: map[string][]string{
				"VULN-1":         {"INTERMEDIATE-A", "INTERMEDIATE-B"},
				"INTERMEDIATE-A": {"ROOT-1"},
				"INTERMEDIATE-B": {"ROOT-2"},
			},
			want: &models.Hierarchy{
				Roots: []string{"ROOT-1", "ROOT-2"},
				Graph: map[string][]string{
					"ROOT-1":         {"INTERMEDIATE-A"},
					"ROOT-2":         {"INTERMEDIATE-B"},
					"INTERMEDIATE-A": {"VULN-1"},
					"INTERMEDIATE-B": {"VULN-1"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Cycle detected",
			targetID: "VULN-1",
			rawHierarchy: map[string][]string{
				"VULN-1": {"VULN-2"},
				"VULN-2": {"VULN-1"},
			},
			want:    nil,
			wantErr: errors.New("cycle detected in upstream hierarchy for VULN-1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeUpstreamHierarchy(tt.targetID, tt.rawHierarchy)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("ComputeUpstreamHierarchy() expected error, got nil")
				}
				if errors.Is(tt.wantErr, models.ErrNotFound) && !errors.Is(err, models.ErrNotFound) {
					t.Fatalf("ComputeUpstreamHierarchy() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("ComputeUpstreamHierarchy() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ComputeUpstreamHierarchy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestComputeDownstreamHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		targetID    string
		downstreams map[string][]string
		want        *models.Hierarchy
		wantErr     error
	}{
		{
			name:        "Empty",
			targetID:    "ROOT-1",
			downstreams: nil,
			want:        nil,
			wantErr:     models.ErrNotFound,
		},
		{
			name:     "Single downstream",
			targetID: "ROOT-1",
			downstreams: map[string][]string{
				"DOWN-1": {"ROOT-1"},
			},
			want: &models.Hierarchy{
				Roots: []string{"DOWN-1"},
				Graph: map[string][]string{
					"ROOT-1": {"DOWN-1"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Transitive downstream chain",
			targetID: "ROOT-1",
			downstreams: map[string][]string{
				"DOWN-1": {"ROOT-1"},
				"DOWN-2": {"ROOT-1", "DOWN-1"},
			},
			want: &models.Hierarchy{
				Roots: []string{"DOWN-1"},
				Graph: map[string][]string{
					"DOWN-1": {"DOWN-2"},
					"ROOT-1": {"DOWN-1"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "3-level transitive downstream chain",
			targetID: "ROOT-1",
			downstreams: map[string][]string{
				"DOWN-1": {"ROOT-1"},
				"DOWN-2": {"ROOT-1", "DOWN-1"},
				"DOWN-3": {"ROOT-1", "DOWN-1", "DOWN-2"},
			},
			want: &models.Hierarchy{
				Roots: []string{"DOWN-1"},
				Graph: map[string][]string{
					"DOWN-1": {"DOWN-2"},
					"DOWN-2": {"DOWN-3"},
					"ROOT-1": {"DOWN-1"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Multi-root branching downstream hierarchy",
			targetID: "ROOT-1",
			downstreams: map[string][]string{
				"DOWN-A": {"ROOT-1"},
				"DOWN-B": {"ROOT-1"},
				"DOWN-C": {"ROOT-1", "DOWN-A"},
			},
			want: &models.Hierarchy{
				Roots: []string{"DOWN-A", "DOWN-B"},
				Graph: map[string][]string{
					"DOWN-A": {"DOWN-C"},
					"ROOT-1": {"DOWN-A", "DOWN-B"},
				},
			},
			wantErr: nil,
		},
		{
			name:     "Cycle detected",
			targetID: "ROOT-1",
			downstreams: map[string][]string{
				"DOWN-1": {"ROOT-1", "DOWN-2"},
				"DOWN-2": {"ROOT-1", "DOWN-1"},
			},
			want:    nil,
			wantErr: errors.New("cycle detected in downstream hierarchy for ROOT-1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeDownstreamHierarchy(tt.targetID, tt.downstreams)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("ComputeDownstreamHierarchy() expected error, got nil")
				}
				if errors.Is(tt.wantErr, models.ErrNotFound) && !errors.Is(err, models.ErrNotFound) {
					t.Fatalf("ComputeDownstreamHierarchy() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("ComputeDownstreamHierarchy() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ComputeDownstreamHierarchy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRelationsStore_GetUpstreamHierarchy(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	upstreamGroup := UpstreamGroup{
		VulnID:            "VULN-1",
		UpstreamIDs:       []string{"ROOT-1"},
		UpstreamHierarchy: []byte(`{"VULN-1": ["ROOT-1"]}`),
		Modified:          time.Now().Truncate(time.Second),
	}

	key := datastore.IncompleteKey("UpstreamGroup", nil)
	if _, err := dsClient.Put(ctx, key, &upstreamGroup); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	got, err := store.GetUpstreamHierarchy(ctx, "VULN-1")
	if err != nil {
		t.Fatalf("GetUpstreamHierarchy() unexpected error: %v", err)
	}
	want := &models.Hierarchy{
		Roots: []string{"ROOT-1"},
		Graph: map[string][]string{
			"ROOT-1": {"VULN-1"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetUpstreamHierarchy() mismatch (-want +got):\n%s", diff)
	}

	// Missing entity should return ErrNotFound
	missing, err := store.GetUpstreamHierarchy(ctx, "NON-EXISTENT")
	if !errors.Is(err, models.ErrNotFound) || missing != nil {
		t.Errorf("expected ErrNotFound for non-existent; got %v, %v", missing, err)
	}
}

func TestRelationsStore_GetDownstreamHierarchy(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewRelationsStore(dsClient)

	group1 := UpstreamGroup{
		VulnID:      "DOWN-1",
		UpstreamIDs: []string{"TARGET-ROOT"},
		Modified:    time.Now().Truncate(time.Second),
	}
	group2 := UpstreamGroup{
		VulnID:      "DOWN-2",
		UpstreamIDs: []string{"TARGET-ROOT", "DOWN-1"},
		Modified:    time.Now().Truncate(time.Second),
	}

	if _, err := dsClient.Put(ctx, datastore.NameKey("UpstreamGroup", "DOWN-1", nil), &group1); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}
	if _, err := dsClient.Put(ctx, datastore.NameKey("UpstreamGroup", "DOWN-2", nil), &group2); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	got, err := store.GetDownstreamHierarchy(ctx, "TARGET-ROOT")
	if err != nil {
		t.Fatalf("GetDownstreamHierarchy() unexpected error: %v", err)
	}
	want := &models.Hierarchy{
		Roots: []string{"DOWN-1"},
		Graph: map[string][]string{
			"DOWN-1":      {"DOWN-2"},
			"TARGET-ROOT": {"DOWN-1"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetDownstreamHierarchy() mismatch (-want +got):\n%s", diff)
	}

	// Non-existent target should return ErrNotFound
	missing, err := store.GetDownstreamHierarchy(ctx, "NON-EXISTENT")
	if !errors.Is(err, models.ErrNotFound) || missing != nil {
		t.Errorf("expected ErrNotFound for non-existent; got %v, %v", missing, err)
	}
}
