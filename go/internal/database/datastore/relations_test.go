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
		UpstreamIDs: []string{"UPSTREAM-1", "UPSTREAM-2"},
		Modified:    now,
	}

	key := datastore.NameKey("UpstreamGroup", "VULN-A", nil)

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
