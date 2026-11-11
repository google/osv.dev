package datastore

import (
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestImportFindingsStore_ListAll(t *testing.T) {
	baseTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("empty store", func(t *testing.T) {
		dsClient := testutils.MustNewDatastoreClientForTesting(t)
		store := NewImportFindingsStore(dsClient, nil, "", "")

		got, err := store.listAll(t.Context(), 2)
		if err != nil {
			t.Fatalf("listAll() unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected 0 findings, got %d", len(got))
		}
	})

	for _, total := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("cursor pagination with %d entities (pageSize=2)", total), func(t *testing.T) {
			dsClient := testutils.MustNewDatastoreClientForTesting(t)
			store := NewImportFindingsStore(dsClient, nil, "", "")

			want := make([]*models.ImportFinding, total)
			for i := range total {
				want[i] = &models.ImportFinding{
					BugID:       fmt.Sprintf("BUG-%04d", i+1),
					Source:      "test-source",
					Findings:    []models.ImportFindings{models.ImportFindingsInvalidJSON},
					FirstSeen:   baseTime.Add(time.Duration(i) * time.Minute),
					LastAttempt: baseTime.Add(time.Duration(i) * time.Hour),
				}
			}
			if err := store.PutMulti(t.Context(), want); err != nil {
				t.Fatalf("PutMulti() error: %v", err)
			}

			got, err := store.listAll(t.Context(), 2)
			if err != nil {
				t.Fatalf("listAll() unexpected error: %v", err)
			}

			sortByID := cmpopts.SortSlices(func(a, b *models.ImportFinding) bool {
				return a.BugID < b.BugID
			})
			if diff := cmp.Diff(want, got, sortByID); diff != "" {
				t.Errorf("listAll() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("falls back to key.Name when bug_id property is empty", func(t *testing.T) {
		dsClient := testutils.MustNewDatastoreClientForTesting(t)
		store := NewImportFindingsStore(dsClient, nil, "", "")

		key := datastore.NameKey("ImportFinding", "KEY-ONLY-BUG-1", nil)
		raw := &ImportFinding{
			BugID:       "",
			Source:      "ghsa",
			FirstSeen:   baseTime,
			LastAttempt: baseTime.Add(10 * time.Minute),
		}
		if _, err := dsClient.Put(t.Context(), key, raw); err != nil {
			t.Fatalf("dsClient.Put() error: %v", err)
		}

		got, err := store.ListAll(t.Context())
		if err != nil {
			t.Fatalf("ListAll() unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].BugID != "KEY-ONLY-BUG-1" {
			t.Errorf("got %+v, want single finding with BugID=KEY-ONLY-BUG-1", got)
		}
	})
}
