package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/testutils"
)

var testNow = time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

// setupBucket creates a mock export bucket. Every object is old, except
// PyPI/NEW-1.json which is newer than the min age.
func setupBucket(t *testing.T) *testutils.MockStorage {
	t.Helper()
	s := testutils.NewMockStorage()
	put := func(path, data string, updated time.Time) {
		if err := s.WriteObject(t.Context(), path, []byte(data), nil); err != nil {
			t.Fatalf("WriteObject(%s) failed: %v", path, err)
		}
		s.SetUpdated(path, updated)
	}
	old := testNow.Add(-2 * time.Hour)

	put("ecosystems.txt", "GIT\nNoCSV\nPyPI\n", old)
	put("PyPI/modified_id.csv", "2026-01-01T00:00:00Z,PYSEC-1\n2026-01-01T00:00:00Z,PYSEC-2\n", old)
	put("GIT/modified_id.csv", "2026-01-01T00:00:00Z,CVE-1\n", old)
	for _, p := range []string{
		"all.zip", "modified_id.csv",
		"PyPI/all.zip", "PyPI/PYSEC-1.json", "PyPI/PYSEC-2.json", "PyPI/DELETED-1.json",
		"GIT/all.zip", "GIT/osv_git.json", "GIT/CVE-1.json", "GIT/DELETED-2.json",
		"NoCSV/X-1.json",                          // Ecosystem without modified_id.csv.
		"OldEco/modified_id.csv", "OldEco/Y.json", // Not in ecosystems.txt.
		"all/pb/DELETED-1.pb",                   // Protos.
		"PyPI:3/Z.json",                         // Folder with a ":" suffix.
		"PyPI/README.txt", "PyPI/nested/X.json", // Not "<ID>.json" directly in the folder.
	} {
		put(p, p, old)
	}
	put("PyPI/NEW-1.json", "new", testNow.Add(-time.Minute))

	return s
}

func listAll(t *testing.T, s *testutils.MockStorage) []string {
	t.Helper()
	var names []string
	for obj, err := range s.Objects(t.Context(), "") {
		if err != nil {
			t.Fatalf("Objects failed: %v", err)
		}
		names = append(names, obj.Name)
	}

	return names
}

func deletedObjects(before, after []string) []string {
	var deleted []string
	for _, name := range before {
		if !slices.Contains(after, name) {
			deleted = append(deleted, name)
		}
	}

	return deleted
}

func testConfig() deleterConfig {
	return deleterConfig{MinAge: time.Hour, ThresholdPct: 100, NumWorkers: 4, Now: func() time.Time { return testNow }}
}

func TestRunDeleter(t *testing.T) {
	s := setupBucket(t)
	before := listAll(t, s)

	if err := runDeleter(t.Context(), s, testConfig()); err != nil {
		t.Fatalf("runDeleter failed: %v", err)
	}

	want := []string{"GIT/DELETED-2.json", "PyPI/DELETED-1.json"}
	if got := deletedObjects(before, listAll(t, s)); !slices.Equal(got, want) {
		t.Errorf("deleted = %v, want %v", got, want)
	}
}

func TestRunDeleter_DryRun(t *testing.T) {
	s := setupBucket(t)
	before := listAll(t, s)

	cfg := testConfig()
	cfg.DryRun = true
	if err := runDeleter(t.Context(), s, cfg); err != nil {
		t.Fatalf("runDeleter failed: %v", err)
	}
	if got := deletedObjects(before, listAll(t, s)); len(got) != 0 {
		t.Errorf("dry run deleted %v", got)
	}
}

func TestRunDeleter_Threshold(t *testing.T) {
	// 3 of 6 vulnerability files (50%) are not in the CSVs. PyPI/NEW-1.json is
	// too new to delete, but still counts towards the threshold.
	for _, tc := range []struct {
		pct         float64
		wantDeleted int
	}{{50, 2}, {49.9, 0}} {
		s := setupBucket(t)
		before := listAll(t, s)

		cfg := testConfig()
		cfg.ThresholdPct = tc.pct
		err := runDeleter(t.Context(), s, cfg)
		gotThresholdErr := err != nil && strings.Contains(err.Error(), "cowardly refusing")
		if wantErr := tc.wantDeleted == 0; gotThresholdErr != wantErr {
			t.Errorf("pct=%v: runDeleter() error = %v, want threshold error: %v", tc.pct, err, wantErr)
		}
		if got := deletedObjects(before, listAll(t, s)); len(got) != tc.wantDeleted {
			t.Errorf("pct=%v: deleted %v, want %d files", tc.pct, got, tc.wantDeleted)
		}
	}
}

func TestRunDeleter_DryRunStillChecksThreshold(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = true
	cfg.ThresholdPct = 10
	if err := runDeleter(t.Context(), setupBucket(t), cfg); err == nil || !strings.Contains(err.Error(), "cowardly refusing") {
		t.Fatalf("runDeleter() error = %v, want threshold error", err)
	}
}

func TestRunDeleter_RacesAreHarmless(t *testing.T) {
	for _, raceErr := range []error{clients.ErrPreconditionFailed, clients.ErrNotFound} {
		s := setupBucket(t)
		s.DeleteErrors["PyPI/DELETED-1.json"] = raceErr

		if err := runDeleter(t.Context(), s, testConfig()); err != nil {
			t.Errorf("%v: runDeleter failed: %v", raceErr, err)
		}
		if slices.Contains(listAll(t, s), "GIT/DELETED-2.json") {
			t.Errorf("%v: expected GIT/DELETED-2.json to be deleted", raceErr)
		}
	}
}

func TestRunDeleter_BadCSV(t *testing.T) {
	s := setupBucket(t)
	if err := s.WriteObject(t.Context(), "PyPI/modified_id.csv", []byte("garbage\n"), nil); err != nil {
		t.Fatalf("WriteObject failed: %v", err)
	}
	before := listAll(t, s)

	err := runDeleter(t.Context(), s, testConfig())
	if err == nil || !strings.Contains(err.Error(), "failed to parse PyPI/modified_id.csv") {
		t.Fatalf("runDeleter() error = %v, want parse error", err)
	}
	if got := deletedObjects(before, listAll(t, s)); len(got) != 0 {
		t.Errorf("deleted %v despite bad CSV", got)
	}
}

func TestRunDeleter_EmptyCSVSkipsEcosystem(t *testing.T) {
	s := setupBucket(t)
	if err := s.WriteObject(t.Context(), "PyPI/modified_id.csv", nil, nil); err != nil {
		t.Fatalf("WriteObject failed: %v", err)
	}
	before := listAll(t, s)

	if err := runDeleter(t.Context(), s, testConfig()); err != nil {
		t.Fatalf("runDeleter failed: %v", err)
	}
	want := []string{"GIT/DELETED-2.json"}
	if got := deletedObjects(before, listAll(t, s)); !slices.Equal(got, want) {
		t.Errorf("deleted = %v, want %v", got, want)
	}
}

func TestRunDeleter_DeleteFailure(t *testing.T) {
	s := setupBucket(t)
	s.DeleteErrors["PyPI/DELETED-1.json"] = errors.New("boom")

	err := runDeleter(t.Context(), s, testConfig())
	if err == nil || !strings.Contains(err.Error(), "failed to delete 1 files") {
		t.Fatalf("runDeleter() error = %v, want delete failure", err)
	}
	if slices.Contains(listAll(t, s), "GIT/DELETED-2.json") {
		t.Error("expected GIT/DELETED-2.json to be deleted despite other failures")
	}
}

func TestRunDeleter_EcosystemsTxt(t *testing.T) {
	err := runDeleter(t.Context(), testutils.NewMockStorage(), testConfig())
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("missing ecosystems.txt: runDeleter() error = %v, want ErrNotFound", err)
	}

	s := testutils.NewMockStorage()
	if err := s.WriteObject(t.Context(), "ecosystems.txt", []byte("\n"), nil); err != nil {
		t.Fatalf("WriteObject failed: %v", err)
	}
	if err := runDeleter(t.Context(), s, testConfig()); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty ecosystems.txt: runDeleter() error = %v, want 'is empty'", err)
	}
}
