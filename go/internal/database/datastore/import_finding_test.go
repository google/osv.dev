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

func TestImportFindingsStore_ListAllAndLastAttempts(t *testing.T) {
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewImportFindingsStore(dsClient, nil, "", "")
	baseTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	want := make([]*models.ImportFinding, 0, 5)
	wantTS := make(map[string]int64, 5)
	for i := range 4 {
		id := fmt.Sprintf("BUG-%04d", i+1)
		la := baseTime.Add(time.Duration(i) * time.Hour)
		want = append(want, &models.ImportFinding{
			BugID:       id,
			Source:      "test-source",
			Findings:    []models.ImportFindings{models.ImportFindingsInvalidJSON},
			FirstSeen:   baseTime,
			LastAttempt: la,
		})
		wantTS[id] = la.Unix()
	}
	if err := store.PutMulti(t.Context(), want); err != nil {
		t.Fatalf("PutMulti() error: %v", err)
	}

	// Fifth entity omits bug_id property to verify key.Name fallback across cursor pages (pageSize=2 -> 3 pages).
	keyOnlyLA := baseTime.Add(10 * time.Hour)
	if _, err := dsClient.Put(t.Context(), datastore.NameKey("ImportFinding", "KEY-ONLY-BUG", nil), &ImportFinding{
		Source:      "ghsa",
		FirstSeen:   baseTime,
		LastAttempt: keyOnlyLA,
	}); err != nil {
		t.Fatalf("dsClient.Put() error: %v", err)
	}
	want = append(want, &models.ImportFinding{BugID: "KEY-ONLY-BUG", Source: "ghsa", FirstSeen: baseTime, LastAttempt: keyOnlyLA})
	wantTS["KEY-ONLY-BUG"] = keyOnlyLA.Unix()

	got, err := store.listAll(t.Context(), 2)
	if err != nil {
		t.Fatalf("listAll() error: %v", err)
	}
	sortByID := cmpopts.SortSlices(func(a, b *models.ImportFinding) bool { return a.BugID < b.BugID })
	if diff := cmp.Diff(want, got, sortByID); diff != "" {
		t.Errorf("listAll() mismatch (-want +got):\n%s", diff)
	}

	gotTS, err := store.listLastAttempts(t.Context(), 2)
	if err != nil {
		t.Fatalf("listLastAttempts() error: %v", err)
	}
	if diff := cmp.Diff(wantTS, gotTS); diff != "" {
		t.Errorf("listLastAttempts() mismatch (-want +got):\n%s", diff)
	}
}
