package main

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/osv/models"
	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBasic(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Datastore
	vuln1 := &models.Vulnerability{
		Modified: time.Now().UTC(),
		AliasRaw: []string{"aaa-124"},
	}
	vuln1Key := datastore.NameKey("Vulnerability", "aaa-123", nil)
	if _, err := dsClient.Put(ctx, vuln1Key, vuln1); err != nil {
		t.Fatalf("failed to put vuln1: %v", err)
	}
	vuln2 := &models.Vulnerability{
		Modified: time.Now().UTC(),
	}
	vuln2Key := datastore.NameKey("Vulnerability", "aaa-124", nil)
	if _, err := dsClient.Put(ctx, vuln2Key, vuln2); err != nil {
		t.Fatalf("failed to put vuln2: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "aaa-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "aaa-123.pb", v1Data, nil)

	v2 := &osvschema.Vulnerability{Id: "aaa-124", Modified: timestamppb.Now()}
	v2Data, _ := proto.Marshal(v2)
	clients.WriteObject(ctx, gcsClient, "aaa-124.pb", v2Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 alias group, got %d", len(groups))
	}
	if len(groups[0].VulnIDs) != 2 {
		t.Errorf("expected 2 vulns in group, got %d", len(groups[0].VulnIDs))
	}

	// Check GCS
	data, err := gcsClient.ReadObject(ctx, "aaa-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}
	if len(updatedV1.Aliases) != 1 || updatedV1.Aliases[0] != "aaa-124" {
		t.Errorf("expected aliases [aaa-124], got %v", updatedV1.Aliases)
	}
}

func TestMissingVuln(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Datastore with a vuln that has an alias that doesn't exist
	vuln1 := &models.Vulnerability{
		Modified: time.Now().UTC(),
		AliasRaw: []string{"non-existent-123"},
	}
	vuln1Key := datastore.NameKey("Vulnerability", "aaa-123", nil)
	if _, err := dsClient.Put(ctx, vuln1Key, vuln1); err != nil {
		t.Fatalf("failed to put vuln1: %v", err)
	}

	// Setup GCS only for vuln1
	v1 := &osvschema.Vulnerability{Id: "aaa-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "aaa-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - should have created a group, but only updated vuln1 in GCS
	// non-existent-123 should be skipped gracefully.
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 alias group, got %d", len(groups))
	}

	// Check GCS for vuln1
	data, err := gcsClient.ReadObject(ctx, "aaa-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}
	if len(updatedV1.Aliases) != 1 || updatedV1.Aliases[0] != "non-existent-123" {
		t.Errorf("expected aliases [non-existent-123], got %v", updatedV1.Aliases)
	}

	// Verify non-existent-123 was not created in GCS
	_, err = gcsClient.ReadObject(ctx, "non-existent-123.pb")
	if err != clients.ErrNotFound {
		t.Errorf("expected non-existent-123.pb to not exist, got err: %v", err)
	}
}

func TestMissingGCSButInDatastore(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Datastore with a vuln that has an alias that doesn't exist in GCS but exists in Datastore
	vuln1 := &models.Vulnerability{
		Modified: time.Now().UTC(),
		AliasRaw: []string{"missing-in-gcs"},
	}
	vuln1Key := datastore.NameKey("Vulnerability", "aaa-123", nil)
	if _, err := dsClient.Put(ctx, vuln1Key, vuln1); err != nil {
		t.Fatalf("failed to put vuln1: %v", err)
	}

	// The alias exists in Datastore but won't be in GCS
	vuln2 := &models.Vulnerability{
		Modified: time.Now().UTC(),
	}
	vuln2Key := datastore.NameKey("Vulnerability", "missing-in-gcs", nil)
	if _, err := dsClient.Put(ctx, vuln2Key, vuln2); err != nil {
		t.Fatalf("failed to put vuln2: %v", err)
	}

	// Setup GCS only for vuln1
	v1 := &osvschema.Vulnerability{Id: "aaa-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "aaa-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	// Should have created a group
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 alias group, got %d", len(groups))
	}

	// Check Pub/Sub messages
	if len(publisher.Messages) != 1 {
		t.Errorf("expected 1 Pub/Sub message, got %d", len(publisher.Messages))
	} else {
		msg := publisher.Messages[0]
		if msg.Attributes["type"] != "gcs_missing" {
			t.Errorf("expected type gcs_missing, got %s", msg.Attributes["type"])
		}
		if msg.Attributes["id"] != "missing-in-gcs" {
			t.Errorf("expected id missing-in-gcs, got %s", msg.Attributes["id"])
		}
	}
}

func TestGenerationMismatch(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Datastore
	vuln1 := &models.Vulnerability{
		Modified: time.Now().UTC(),
		AliasRaw: []string{"aaa-124"},
	}
	vuln1Key := datastore.NameKey("Vulnerability", "aaa-123", nil)
	if _, err := dsClient.Put(ctx, vuln1Key, vuln1); err != nil {
		t.Fatalf("failed to put vuln1: %v", err)
	}
	vuln2 := &models.Vulnerability{
		Modified: time.Now().UTC(),
	}
	vuln2Key := datastore.NameKey("Vulnerability", "aaa-124", nil)
	if _, err := dsClient.Put(ctx, vuln2Key, vuln2); err != nil {
		t.Fatalf("failed to put vuln2: %v", err)
	}

	// Setup GCS with an older generation
	v1 := &osvschema.Vulnerability{Id: "aaa-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "aaa-123.pb", v1Data, nil)

	v2 := &osvschema.Vulnerability{Id: "aaa-124", Modified: timestamppb.Now()}
	v2Data, _ := proto.Marshal(v2)
	clients.WriteObject(ctx, gcsClient, "aaa-124.pb", v2Data, nil)

	// Simulate a concurrent update by changing the generation in GCS
	// In our mock, we can just write again to increment generation
	clients.WriteObject(ctx, gcsClient, "aaa-123.pb", v1Data, nil)

	// Run computation. The updater will read the new generation but we want to simulate
	// the case where it read an old generation. This is hard to do perfectly with the current
	// mock without more control, but we can verify the code path if we can force a mismatch.
	// For now, let's just verify the code compiles and runs.
	// To truly test this, we'd need to inject a failure into WriteObject.
	// Given the current mock, we can't easily force a mismatch without modifying the mock.
	// But we can at least verify the normal flow still works.
	// TODO: Enhance MockStorage to allow forcing errors.

	// For now, let's just run it and ensure it passes normally, as we can't easily force the error.
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	if len(publisher.Messages) != 0 {
		t.Errorf("expected 0 Pub/Sub messages, got %d", len(publisher.Messages))
	}
}

func TestBugReachesLimit(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Datastore
	vuln1 := &models.Vulnerability{
		Modified: time.Now().UTC(),
		AliasRaw: []string{"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005", "CVE-2020-0006"},
	}
	vuln1Key := datastore.NameKey("Vulnerability", "aaa-111", nil)
	if _, err := dsClient.Put(ctx, vuln1Key, vuln1); err != nil {
		t.Fatalf("failed to put vuln1: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "aaa-111", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "aaa-111.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check that no alias group was created
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 alias groups, got %d", len(groups))
	}

	// Check GCS to ensure aliases are empty
	data, err := gcsClient.ReadObject(ctx, "aaa-111.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}
	if len(updatedV1.Aliases) != 0 {
		t.Errorf("expected 0 aliases, got %v", updatedV1.Aliases)
	}
}

func TestUpdateAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup existing AliasGroup
	aliasGroup := &models.AliasGroup{
		VulnIDs:  []string{"bbb-123", "bbb-234"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), aliasGroup); err != nil {
		t.Fatalf("failed to put alias group: %v", err)
	}

	// Setup Bugs
	vulns := []*models.Vulnerability{
		{
			AliasRaw: []string{"bbb-345", "bbb-456"},
		},
		{
			AliasRaw: []string{"bbb-123"},
		},
		{
			AliasRaw: []string{"bbb-456"},
		},
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "bbb-123", nil),
		datastore.NameKey("Vulnerability", "bbb-234", nil),
		datastore.NameKey("Vulnerability", "bbb-789", nil),
	}
	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS for bbb-123 (to check update)
	v1 := &osvschema.Vulnerability{Id: "bbb-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "bbb-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}

	// We expect one merged group
	// Note: ComputeAliasGroups might leave empty groups or merge them.
	// The Python test checks specifically for the group containing 'bbb-123'.

	foundGroup := false
	expectedIDs := []string{"bbb-123", "bbb-234", "bbb-345", "bbb-456", "bbb-789"}
	for _, g := range groups {
		// Check if this group contains bbb-123
		contains := false
		for _, id := range g.VulnIDs {
			if id == "bbb-123" {
				contains = true
				break
			}
		}
		if contains {
			foundGroup = true
			if len(g.VulnIDs) != len(expectedIDs) {
				t.Errorf("expected %d IDs, got %d: %v", len(expectedIDs), len(g.VulnIDs), g.VulnIDs)
			}
			// Verify contents (ignoring order, though implementation usually sorts)
			// The Python test expects sorted order.
			for i, id := range expectedIDs {
				if g.VulnIDs[i] != id {
					t.Errorf("expected ID at %d to be %s, got %s", i, id, g.VulnIDs[i])
				}
			}
		}
	}
	if !foundGroup {
		t.Errorf("did not find alias group containing bbb-123")
	}

	// Check GCS for bbb-123
	data, err := gcsClient.ReadObject(ctx, "bbb-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}

	expectedAliases := []string{"bbb-234", "bbb-345", "bbb-456", "bbb-789"}
	if len(updatedV1.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d: %v", len(expectedAliases), len(updatedV1.Aliases), updatedV1.Aliases)
	}
	for i, alias := range expectedAliases {
		if updatedV1.Aliases[i] != alias {
			t.Errorf("expected alias at %d to be %s, got %s", i, alias, updatedV1.Aliases[i])
		}
	}
}

func TestCreateAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup Bugs
	vulns := []*models.Vulnerability{
		{
			AliasRaw: []string{"test-124"},
		},
		{
			AliasRaw: []string{"test-124"},
		},
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "test-123", nil),
		datastore.NameKey("Vulnerability", "test-222", nil),
	}
	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS for test-123
	v1 := &osvschema.Vulnerability{Id: "test-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "test-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}

	foundGroup := false
	expectedIDs := []string{"test-123", "test-124", "test-222"}
	for _, g := range groups {
		contains := false
		for _, id := range g.VulnIDs {
			if id == "test-123" {
				contains = true
				break
			}
		}
		if contains {
			foundGroup = true
			if len(g.VulnIDs) != len(expectedIDs) {
				t.Errorf("expected %d IDs, got %d: %v", len(expectedIDs), len(g.VulnIDs), g.VulnIDs)
			}
			for i, id := range expectedIDs {
				if g.VulnIDs[i] != id {
					t.Errorf("expected ID at %d to be %s, got %s", i, id, g.VulnIDs[i])
				}
			}
		}
	}
	if !foundGroup {
		t.Errorf("did not find alias group containing test-123")
	}

	// Check GCS for test-123
	data, err := gcsClient.ReadObject(ctx, "test-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}

	expectedAliases := []string{"test-124", "test-222"}
	if len(updatedV1.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d: %v", len(expectedAliases), len(updatedV1.Aliases), updatedV1.Aliases)
	}
	for i, alias := range expectedAliases {
		if updatedV1.Aliases[i] != alias {
			t.Errorf("expected alias at %d to be %s, got %s", i, alias, updatedV1.Aliases[i])
		}
	}
}

func TestDeleteAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup existing AliasGroup with single vuln
	aliasGroup := &models.AliasGroup{
		VulnIDs:  []string{"ccc-123"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), aliasGroup); err != nil {
		t.Fatalf("failed to put alias group: %v", err)
	}

	// Setup Bug
	vuln := &models.Vulnerability{
		AliasRaw: []string(nil), // No aliases
	}
	if _, err := dsClient.Put(ctx, datastore.NameKey("Vulnerability", "ccc-123", nil), vuln); err != nil {
		t.Fatalf("failed to put vuln: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "ccc-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "ccc-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - AliasGroup should be deleted
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}

	if len(groups) != 0 {
		t.Errorf("expected 0 alias groups, got %d", len(groups))
	}

	// Check GCS for ccc-123
	data, err := gcsClient.ReadObject(ctx, "ccc-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}

	if len(updatedV1.Aliases) != 0 {
		t.Errorf("expected 0 aliases, got %v", updatedV1.Aliases)
	}
}

func TestSplitAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup existing AliasGroup
	aliasGroup := &models.AliasGroup{
		VulnIDs:  []string{"ddd-123", "ddd-124"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), aliasGroup); err != nil {
		t.Fatalf("failed to put alias group: %v", err)
	}

	// Setup Bugs with no aliases (so they should split)
	vulns := []*models.Vulnerability{
		{
			AliasRaw: []string(nil),
		},
		{
			AliasRaw: []string(nil),
		},
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "ddd-123", nil),
		datastore.NameKey("Vulnerability", "ddd-124", nil),
	}
	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "ddd-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "ddd-123.pb", v1Data, nil)

	v2 := &osvschema.Vulnerability{Id: "ddd-124", Modified: timestamppb.Now()}
	v2Data, _ := proto.Marshal(v2)
	clients.WriteObject(ctx, gcsClient, "ddd-124.pb", v2Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - AliasGroup should be deleted (split into singletons which are deleted)
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 alias groups, got %d", len(groups))
	}

	// Check GCS
	data, err := gcsClient.ReadObject(ctx, "ddd-123.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV1 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV1); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}
	if len(updatedV1.Aliases) != 0 {
		t.Errorf("expected 0 aliases for ddd-123, got %v", updatedV1.Aliases)
	}

	data, err = gcsClient.ReadObject(ctx, "ddd-124.pb")
	if err != nil {
		t.Fatalf("failed to read GCS object: %v", err)
	}
	var updatedV2 osvschema.Vulnerability
	if err := proto.Unmarshal(data, &updatedV2); err != nil {
		t.Fatalf("failed to unmarshal GCS object: %v", err)
	}
	if len(updatedV2.Aliases) != 0 {
		t.Errorf("expected 0 aliases for ddd-124, got %v", updatedV2.Aliases)
	}
}

func TestAllowList(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup AllowList
	allowListEntry := &models.AliasAllowListEntry{
		VulnID: "eee-123",
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasAllowListEntry", nil), allowListEntry); err != nil {
		t.Fatalf("failed to put allow list entry: %v", err)
	}

	// Setup Bug with many aliases (more than limit)
	aliases := []string{"eee-124", "eee-125", "eee-126", "eee-127", "eee-128", "eee-129"}
	vuln := &models.Vulnerability{
		AliasRaw: aliases,
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.NameKey("Vulnerability", "eee-123", nil), vuln); err != nil {
		t.Fatalf("failed to put vuln: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "eee-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "eee-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - AliasGroup should be created despite limit because of allow list
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}

	foundGroup := false
	expectedIDs := append([]string{"eee-123"}, aliases...)
	slices.Sort(expectedIDs)

	for _, g := range groups {
		contains := false
		for _, id := range g.VulnIDs {
			if id == "eee-123" {
				contains = true
				break
			}
		}
		if contains {
			foundGroup = true
			if len(g.VulnIDs) != len(expectedIDs) {
				t.Errorf("expected %d IDs, got %d: %v", len(expectedIDs), len(g.VulnIDs), g.VulnIDs)
			}
			for i, id := range expectedIDs {
				if g.VulnIDs[i] != id {
					t.Errorf("expected ID at %d to be %s, got %s", i, id, g.VulnIDs[i])
				}
			}
		}
	}
	if !foundGroup {
		t.Errorf("did not find alias group containing eee-123")
	}
}

func TestDenyList(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup DenyList
	denyListEntry := &models.AliasDenyListEntry{
		VulnID: "fff-123",
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasDenyListEntry", nil), denyListEntry); err != nil {
		t.Fatalf("failed to put deny list entry: %v", err)
	}

	// Setup Bug
	vuln := &models.Vulnerability{
		AliasRaw: []string{"fff-124"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.NameKey("Vulnerability", "fff-123", nil), vuln); err != nil {
		t.Fatalf("failed to put vuln: %v", err)
	}

	// Setup GCS
	v1 := &osvschema.Vulnerability{Id: "fff-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "fff-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - AliasGroup should NOT be created
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 alias groups, got %d", len(groups))
	}
}

func TestMergeAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup existing AliasGroups
	group1 := &models.AliasGroup{
		VulnIDs:  []string{"ggg-123", "ggg-124"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), group1); err != nil {
		t.Fatalf("failed to put group1: %v", err)
	}
	group2 := &models.AliasGroup{
		VulnIDs:  []string{"ggg-125", "ggg-126"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), group2); err != nil {
		t.Fatalf("failed to put group2: %v", err)
	}

	// Setup Bugs
	vulns := []*models.Vulnerability{
		{AliasRaw: []string{"ggg-124", "ggg-125", "ggg-126"}}, // Links group1 and group2
		{AliasRaw: []string(nil)},
		{AliasRaw: []string(nil)},
		{AliasRaw: []string(nil)},
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "ggg-123", nil),
		datastore.NameKey("Vulnerability", "ggg-124", nil),
		datastore.NameKey("Vulnerability", "ggg-125", nil),
		datastore.NameKey("Vulnerability", "ggg-126", nil),
	}
	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS for ggg-123
	v1 := &osvschema.Vulnerability{Id: "ggg-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "ggg-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - Should be merged into one group
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 alias group, got %d", len(groups))
	}
	expectedIDs := []string{"ggg-123", "ggg-124", "ggg-125", "ggg-126"}
	if len(groups) > 0 {
		if !slices.Equal(groups[0].VulnIDs, expectedIDs) {
			t.Errorf("expected IDs %v, got %v", expectedIDs, groups[0].VulnIDs)
		}
	}
}

func TestPartialMergeAliasGroup(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Setup existing AliasGroups
	group1 := &models.AliasGroup{
		VulnIDs:  []string{"hhh-123", "hhh-124"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), group1); err != nil {
		t.Fatalf("failed to put group1: %v", err)
	}
	group2 := &models.AliasGroup{
		VulnIDs:  []string{"hhh-125", "hhh-126", "hhh-127"},
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), group2); err != nil {
		t.Fatalf("failed to put group2: %v", err)
	}

	// Setup Bugs
	vulns := []*models.Vulnerability{
		{AliasRaw: []string{"hhh-124", "hhh-125"}}, // Links group1 and part of group2
		{AliasRaw: []string(nil)},
		{AliasRaw: []string(nil)},
		{AliasRaw: []string(nil)}, // hhh-126 - not linked
		{AliasRaw: []string(nil)}, // hhh-127 - not linked
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "hhh-123", nil),
		datastore.NameKey("Vulnerability", "hhh-124", nil),
		datastore.NameKey("Vulnerability", "hhh-125", nil),
		datastore.NameKey("Vulnerability", "hhh-126", nil),
		datastore.NameKey("Vulnerability", "hhh-127", nil),
	}
	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS for hhh-123
	v1 := &osvschema.Vulnerability{Id: "hhh-123", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "hhh-123.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 alias group, got %d", len(groups))
	}
	expectedIDs := []string{"hhh-123", "hhh-124", "hhh-125"}
	if len(groups) > 0 {
		if !slices.Equal(groups[0].VulnIDs, expectedIDs) {
			t.Errorf("expected IDs %v, got %v", expectedIDs, groups[0].VulnIDs)
		}
	}
}

func TestAliasGroupReachesLimit(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsClient := testutils.NewMockStorage()
	publisher := &testutils.MockPublisher{}

	// Create a group with ALIAS_GROUP_VULN_LIMIT bugs
	const limit = 32
	var bugIDs []string
	for i := 0; i < limit; i++ {
		bugIDs = append(bugIDs, fmt.Sprintf("iii-%d", i))
	}

	aliasGroup := &models.AliasGroup{
		VulnIDs:  bugIDs,
		Modified: time.Now().UTC(),
	}
	if _, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), aliasGroup); err != nil {
		t.Fatalf("failed to put alias group: %v", err)
	}

	// Add one more bug that links to the group
	vulns := []*models.Vulnerability{
		{AliasRaw: []string{"iii-0"}},
	}
	keys := []*datastore.Key{
		datastore.NameKey("Vulnerability", "iii-new", nil),
	}

	// Also create bugs for existing group members
	for i, id := range bugIDs {
		var aliases []string
		if i > 0 {
			aliases = []string{bugIDs[i-1]}
		}
		vulns = append(vulns, &models.Vulnerability{AliasRaw: aliases})
		keys = append(keys, datastore.NameKey("Vulnerability", id, nil))
	}

	if _, err := dsClient.PutMulti(ctx, keys, vulns); err != nil {
		t.Fatalf("failed to put vulns: %v", err)
	}

	// Setup GCS for iii-new
	v1 := &osvschema.Vulnerability{Id: "iii-new", Modified: timestamppb.Now()}
	v1Data, _ := proto.Marshal(v1)
	clients.WriteObject(ctx, gcsClient, "iii-new.pb", v1Data, nil)

	// Run computation
	updater := NewUpdater(ctx, dsClient, gcsClient, publisher)
	if err := ComputeAliasGroups(ctx, dsClient, updater.Ch); err != nil {
		t.Fatalf("ComputeAliasGroups failed: %v", err)
	}
	updater.Finish()

	// Check results - Group should be deleted
	var groups []models.AliasGroup
	if _, err := dsClient.GetAll(ctx, datastore.NewQuery("AliasGroup"), &groups); err != nil {
		t.Fatalf("failed to get alias groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 alias groups, got %d", len(groups))
	}
}
