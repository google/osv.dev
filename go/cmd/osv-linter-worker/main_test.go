package main

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/linter"
	internalmodels "github.com/google/osv.dev/go/internal/models"
)

type fakeImportFindingsStore struct {
	internalmodels.UnimplementedImportFindingsStore

	mu          sync.Mutex
	existing    map[string]*internalmodels.ImportFinding
	uploadedGCS map[string][]byte
	deletedGCS  []string
}

func newFakeImportFindingsStore(initial map[string]*internalmodels.ImportFinding) *fakeImportFindingsStore {
	cloned := make(map[string]*internalmodels.ImportFinding, len(initial))
	maps.Copy(cloned, initial)

	return &fakeImportFindingsStore{
		existing:    cloned,
		uploadedGCS: make(map[string][]byte),
	}
}

func (s *fakeImportFindingsStore) ListIDs(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Collect(maps.Keys(s.existing)), nil
}

func (s *fakeImportFindingsStore) GetMulti(_ context.Context, bugIDs []string) ([]*internalmodels.ImportFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*internalmodels.ImportFinding, len(bugIDs))
	for i, id := range bugIDs {
		out[i] = s.existing[id]
	}

	return out, nil
}

func (s *fakeImportFindingsStore) PutMulti(_ context.Context, findings []*internalmodels.ImportFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, f := range findings {
		if f != nil {
			cp := *f
			cp.Findings = slices.Clone(f.Findings)
			s.existing[f.BugID] = &cp
		}
	}

	return nil
}

func (s *fakeImportFindingsStore) DeleteMulti(_ context.Context, bugIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range bugIDs {
		delete(s.existing, id)
	}

	return nil
}

func (s *fakeImportFindingsStore) ListResultSources(_ context.Context) ([]string, error) {
	return nil, nil
}

func (s *fakeImportFindingsStore) UploadResult(_ context.Context, source string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.uploadedGCS[source] = slices.Clone(data)

	return nil
}

func (s *fakeImportFindingsStore) DeleteResult(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deletedGCS = append(s.deletedGCS, name)

	return nil
}

func TestProcessLinterResult_HybridSuppressions(t *testing.T) {
	t.Parallel()

	oldFirstSeen := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	store := newFakeImportFindingsStore(map[string]*internalmodels.ImportFinding{
		// Previously stored before suppressions existed; should be deleted from Datastore now.
		"CGA-ONLY-ZERO": {
			BugID:     "CGA-ONLY-ZERO",
			Source:    "chainguard",
			Findings:  []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidRange},
			FirstSeen: oldFirstSeen,
		},
		// Mixed record previously had InvalidJSON + InvalidRange; should update to InvalidJSON only and keep FirstSeen.
		"CGA-MIXED": {
			BugID:     "CGA-MIXED",
			Source:    "chainguard",
			Findings:  []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidJSON, internalmodels.ImportFindingsInvalidRange},
			FirstSeen: oldFirstSeen,
		},
	})

	prefixToSource := map[string]string{
		"CGA-":      "chainguard",
		"GHSA-":     "ghsa",
		"ASB-":      "generic-asb",
		"ASB-A-":    "android",
		"SUSE-":     "suse",
		"openSUSE-": "suse",
	}

	linterJSON := `{
		"tmp/CGA-ONLY-ZERO.json": [
			{"Code": "RNG:002", "Message": "overlapping event: \"0\""}
		],
		"tmp/CGA-MIXED.json": [
			{"Code": "RNG:002", "Message": "overlapping event: \"0\""},
			{"Code": "SCH:001", "Message": "Record does not conform to schema"}
		],
		"tmp/CGA-REAL-OVERLAP.json": [
			{"Code": "RNG:002", "Message": "overlapping event: \"1.2.3\""}
		],
		"tmp/GHSA-ZERO-OVERLAP.json": [
			{"Code": "RNG:002", "Message": "overlapping event: \"0\""}
		],
		"tmp/ASB-A-2026-01.json": [
			{"Code": "REC:001", "Message": "Invalid Affected"}
		],
		"tmp/SUSE-SU-2024:0001-1.json": [
			{"Code": "REC:003", "Message": "Invalid Upstream: upstream should not contain related IDs"}
		],
		"tmp/openSUSE-SU-2024:0002-1.json": [
			{"Code": "REC:003", "Message": "Invalid Upstream: upstream should not contain related IDs"},
			{"Code": "REC:003", "Message": "Invalid Upstream: upstream should not contain itself"}
		]
	}`

	err := processLinterResult(context.Background(), store, []byte(linterJSON), prefixToSource, linter.DefaultRegistry(), false)
	if err != nil {
		t.Fatalf("processLinterResult failed: %v", err)
	}

	// 1. Fully suppressed Chainguard and SUSE records must not exist in Datastore.
	if _, exists := store.existing["CGA-ONLY-ZERO"]; exists {
		t.Error("expected CGA-ONLY-ZERO to be deleted from Datastore ImportFindings")
	}
	if _, exists := store.existing["SUSE-SU-2024:0001-1"]; exists {
		t.Error("expected SUSE-SU-2024:0001-1 to be excluded from Datastore ImportFindings")
	}
	if opensuseRec, ok := store.existing["openSUSE-SU-2024:0002-1"]; !ok || !slices.Equal(opensuseRec.Findings, []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidUpstream}) {
		t.Errorf("expected openSUSE-SU-2024:0002-1 to keep non-suppressed REC:003 finding in Datastore, got %+v", opensuseRec)
	}

	// 2. Mixed Chainguard record keeps only InvalidJSON in Datastore while preserving FirstSeen.
	mixed, ok := store.existing["CGA-MIXED"]
	if !ok {
		t.Fatal("expected CGA-MIXED to remain in Datastore ImportFindings")
	}
	if !slices.Equal(mixed.Findings, []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidJSON}) {
		t.Errorf("CGA-MIXED findings = %v, want [ImportFindingsInvalidJSON]", mixed.Findings)
	}
	if !mixed.FirstSeen.Equal(oldFirstSeen) {
		t.Errorf("CGA-MIXED FirstSeen = %v, want %v", mixed.FirstSeen, oldFirstSeen)
	}

	// 3. Non-zero overlap on Chainguard and zero overlap on GHSA remain active in Datastore.
	if realOverlap, ok := store.existing["CGA-REAL-OVERLAP"]; !ok || !slices.Equal(realOverlap.Findings, []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidRange}) {
		t.Errorf("expected CGA-REAL-OVERLAP active InvalidRange in Datastore, got %+v", realOverlap)
	}
	if ghsaOverlap, ok := store.existing["GHSA-ZERO-OVERLAP"]; !ok || !slices.Equal(ghsaOverlap.Findings, []internalmodels.ImportFindings{internalmodels.ImportFindingsInvalidRange}) {
		t.Errorf("expected GHSA-ZERO-OVERLAP active InvalidRange in Datastore, got %+v", ghsaOverlap)
	}
	if androidRec, ok := store.existing["ASB-A-2026-01"]; !ok || androidRec.Source != "android" {
		t.Errorf("expected longest-prefix match ASB-A-2026-01 -> android, got %+v", androidRec)
	}

	// 4. GCS chainguard/result.json still retains suppressed findings tagged with Suppressed=true and SuppressedReason.
	var cgaGCS map[string][]map[string]any
	if err := json.Unmarshal(store.uploadedGCS["chainguard"], &cgaGCS); err != nil {
		t.Fatalf("failed unmarshaling uploaded chainguard GCS JSON: %v", err)
	}
	onlyZeroGCS := cgaGCS["tmp/CGA-ONLY-ZERO.json"]
	if len(onlyZeroGCS) != 1 || onlyZeroGCS[0]["Suppressed"] != true || onlyZeroGCS[0]["SuppressedReason"] == "" {
		t.Errorf("expected tmp/CGA-ONLY-ZERO.json in GCS with Suppressed=true and reason, got %+v", onlyZeroGCS)
	}
	mixedGCS := cgaGCS["tmp/CGA-MIXED.json"]
	if len(mixedGCS) != 2 || mixedGCS[0]["Suppressed"] != true || mixedGCS[1]["Suppressed"] != nil {
		t.Errorf("unexpected tmp/CGA-MIXED.json suppression tags in GCS: %+v", mixedGCS)
	}
	realGCS := cgaGCS["tmp/CGA-REAL-OVERLAP.json"]
	if len(realGCS) != 1 || realGCS[0]["Suppressed"] != nil {
		t.Errorf("expected tmp/CGA-REAL-OVERLAP.json not to be tagged Suppressed, got %+v", realGCS)
	}
}
