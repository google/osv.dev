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
	"context"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	domainmodels "github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/osv/models"
	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockPGVulnStore struct {
	domainmodels.UnimplementedVulnerabilityStore

	vulns map[string]*osvschema.Vulnerability
}

func (m *mockPGVulnStore) Mutate(_ context.Context, id string, mutateFn domainmodels.MutateFunc) (bool, error) {
	v, ok := m.vulns[id]
	if !ok {
		return false, domainmodels.ErrNotFound
	}
	cloned := proto.Clone(v).(*osvschema.Vulnerability)
	changed, err := mutateFn(cloned)
	if err != nil {
		return false, err
	}
	if changed {
		m.vulns[id] = cloned
	}

	return changed, nil
}

func TestUpdater_PostgresModifiedMonotonic(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	pubMock := &testutils.MockPublisher{}

	oldTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updateTime := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	newerPGTime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	futurePGTime := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	pgStoreVulns := make(map[string]*osvschema.Vulnerability)
	setupVuln := func(id string, gcsModified, pgModified time.Time) {
		t.Helper()
		v := &osvschema.Vulnerability{
			Id:       id,
			Modified: timestamppb.New(gcsModified),
		}
		pb, err := proto.Marshal(v)
		if err != nil {
			t.Fatalf("proto.Marshal(%s): %v", id, err)
		}
		if err := gcsMock.WriteObject(ctx, "all/pb/"+id+".pb", pb, nil); err != nil {
			t.Fatalf("gcsMock.WriteObject(%s): %v", id, err)
		}
		if _, err := dsClient.Put(ctx, datastore.NameKey("Vulnerability", id, nil), &models.Vulnerability{
			Modified: gcsModified,
		}); err != nil {
			t.Fatalf("dsClient.Put(%s): %v", id, err)
		}
		pgV := proto.Clone(v).(*osvschema.Vulnerability)
		pgV.Modified = timestamppb.New(pgModified)
		pgStoreVulns[id] = pgV
	}

	setupVuln("OSV-OLDER-PG", oldTime, oldTime)
	setupVuln("OSV-STALE-UPDATE", newerPGTime, newerPGTime)
	setupVuln("OSV-NEWER-PG", oldTime, newerPGTime)
	setupVuln("OSV-FUTURE-PG", oldTime, futurePGTime)

	pgStore := &mockPGVulnStore{vulns: pgStoreVulns}
	beforeRun := time.Now().UTC().Truncate(time.Microsecond)

	updater := NewUpdaterWithPostgres(ctx, dsClient, gcsMock, pubMock, pgStore)
	updater.Ch <- Update{ID: "OSV-OLDER-PG", Timestamp: updateTime, Field: updateFieldAlias, Value: []string{"CVE-1"}}
	updater.Ch <- Update{ID: "OSV-STALE-UPDATE", Timestamp: updateTime, Field: updateFieldAlias, Value: []string{"CVE-1B"}}
	updater.Ch <- Update{ID: "OSV-NEWER-PG", Timestamp: updateTime, Field: updateFieldAlias, Value: []string{"CVE-2"}}
	updater.Ch <- Update{ID: "OSV-FUTURE-PG", Timestamp: updateTime, Field: updateFieldAlias, Value: []string{"CVE-3"}}
	updater.Finish()

	// Case 1: updateTime is newer than both GCS and PG -> uses updateTime everywhere.
	if got := pgStore.vulns["OSV-OLDER-PG"].GetModified().AsTime(); !got.Equal(updateTime) {
		t.Errorf("OSV-OLDER-PG modified = %v, want %v", got, updateTime)
	}

	// Case 2: updateTime is older than both GCS and PG (e.g. stale cached group.Modified)
	// -> advances once to now and shares the exact same timestamp across Datastore, GCS, and PG.
	stalePGMod := pgStore.vulns["OSV-STALE-UPDATE"].GetModified().AsTime()
	if stalePGMod.Before(beforeRun) {
		t.Errorf("OSV-STALE-UPDATE PG modified = %v, expected >= %v", stalePGMod, beforeRun)
	}
	gcsData, err := gcsMock.ReadObject(ctx, "all/pb/OSV-STALE-UPDATE.pb")
	if err != nil {
		t.Fatalf("gcsMock.ReadObject(OSV-STALE-UPDATE): %v", err)
	}
	var staleGCSVuln osvschema.Vulnerability
	if err := proto.Unmarshal(gcsData, &staleGCSVuln); err != nil {
		t.Fatalf("proto.Unmarshal(OSV-STALE-UPDATE): %v", err)
	}
	if got := staleGCSVuln.GetModified().AsTime(); !got.Equal(stalePGMod) {
		t.Errorf("OSV-STALE-UPDATE GCS modified = %v, want exact match with PG %v", got, stalePGMod)
	}
	var staleDSVuln models.Vulnerability
	if err := dsClient.Get(ctx, datastore.NameKey("Vulnerability", "OSV-STALE-UPDATE", nil), &staleDSVuln); err != nil {
		t.Fatalf("dsClient.Get(OSV-STALE-UPDATE): %v", err)
	}
	if !staleDSVuln.Modified.Equal(stalePGMod) {
		t.Errorf("OSV-STALE-UPDATE Datastore modified = %v, want exact match with PG %v", staleDSVuln.Modified, stalePGMod)
	}

	// Case 3: PG's modified is newer than updateTime (concurrent worker wrote PG) -> advances to now, never rewinds.
	if got := pgStore.vulns["OSV-NEWER-PG"].GetModified().AsTime(); got.Before(beforeRun) {
		t.Errorf("OSV-NEWER-PG modified = %v, expected >= %v (must not rewind to %v)", got, beforeRun, updateTime)
	}

	// Case 4: PG's modified is even newer than now (clock skew) -> keeps existing PG modified.
	if got := pgStore.vulns["OSV-FUTURE-PG"].GetModified().AsTime(); !got.Equal(futurePGTime) {
		t.Errorf("OSV-FUTURE-PG modified = %v, want %v", got, futurePGTime)
	}
}
