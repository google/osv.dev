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

package recoverer_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub/v2"
	"github.com/google/go-cmp/cmp"
	osvdatastore "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/gitter"
	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/recoverer"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockGitterClient struct {
	fileContentFunc func(ctx context.Context, req *gitterpb.FileContentRequest) (*gitterpb.FileContentResponse, error)
}

func (m *mockGitterClient) GetGit(_ context.Context, _ string, _ bool) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) Cache(_ context.Context, _ string) error {
	return nil
}

func (m *mockGitterClient) GetTags(_ context.Context, _ string) (*gitterpb.TagsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetAffectedCommits(_ context.Context, _ *gitterpb.AffectedCommitsRequest) (*gitterpb.AffectedCommitsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetFileDiffs(_ context.Context, _ *gitterpb.FileDiffsRequest) (*gitterpb.FileDiffsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockGitterClient) GetFileContent(ctx context.Context, req *gitterpb.FileContentRequest) (*gitterpb.FileContentResponse, error) {
	if m.fileContentFunc != nil {
		return m.fileContentFunc(ctx, req)
	}

	return &gitterpb.FileContentResponse{}, nil
}

var _ gitter.Client = (*mockGitterClient)(nil)

type mockStorageProvider struct {
	storage clients.CloudStorage
}

func (m *mockStorageProvider) Bucket(_ string) clients.CloudStorage {
	return m.storage
}

func TestHandleGCSRetry(t *testing.T) {
	ctx := context.Background()
	gcsMock := testutils.NewMockStorage()

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			GCS: gcsMock,
		},
	})

	modified := time.Date(2025, 5, 5, 0, 0, 0, 0, time.UTC)
	vuln := &osvschema.Vulnerability{
		Id:       "TEST-555",
		Modified: timestamppb.New(modified),
	}
	vulnBytes, err := proto.Marshal(vuln)
	if err != nil {
		t.Fatalf("Failed to marshal proto: %v", err)
	}

	msg := &pubsub.Message{
		Data: vulnBytes,
	}

	if err := rec.HandleGCSRetry(ctx, msg); err != nil {
		t.Fatalf("HandleGCSRetry failed: %v", err)
	}

	// Verify object was written to GCS
	attrs, err := gcsMock.ReadObjectAttrs(ctx, "all/pb/TEST-555.pb")
	if err != nil {
		t.Fatalf("Failed to read object attrs: %v", err)
	}
	if !attrs.CustomTime.Equal(modified) {
		t.Errorf("CustomTime mismatch: got %v, want %v", attrs.CustomTime, modified)
	}

	data, err := gcsMock.ReadObject(ctx, "all/pb/TEST-555.pb")
	if err != nil {
		t.Fatalf("Failed to read object data: %v", err)
	}
	var storedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(data, &storedVuln); err != nil {
		t.Fatalf("Failed to unmarshal stored proto: %v", err)
	}
	if diff := cmp.Diff(vuln, &storedVuln, protocmp.Transform()); diff != "" {
		t.Errorf("Stored proto mismatch (-want +got):\n%s", diff)
	}
}

func TestHandleGCSRetry_Overwritten(t *testing.T) {
	ctx := context.Background()
	gcsMock := testutils.NewMockStorage()

	// Initial newer object in GCS
	newerTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	initialVuln := &osvschema.Vulnerability{
		Id:       "TEST-123",
		Modified: timestamppb.New(newerTime),
	}
	initialBytes, err := proto.Marshal(initialVuln)
	if err != nil {
		t.Fatalf("Failed to marshal proto: %v", err)
	}
	err = gcsMock.WriteObject(ctx, "all/pb/TEST-123.pb", initialBytes, &clients.WriteOptions{
		CustomTime: &newerTime,
	})
	if err != nil {
		t.Fatalf("Failed to write initial object: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			GCS: gcsMock,
		},
	})

	// Older message
	olderTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	olderVuln := &osvschema.Vulnerability{
		Id:       "TEST-123",
		Modified: timestamppb.New(olderTime),
	}
	olderBytes, err := proto.Marshal(olderVuln)
	if err != nil {
		t.Fatalf("Failed to marshal proto: %v", err)
	}

	msg := &pubsub.Message{
		Data: olderBytes,
	}

	if err := rec.HandleGCSRetry(ctx, msg); err != nil {
		t.Fatalf("HandleGCSRetry returned error: %v", err)
	}

	// Verify the object in GCS remains the newer one
	attrs, err := gcsMock.ReadObjectAttrs(ctx, "all/pb/TEST-123.pb")
	if err != nil {
		t.Fatalf("Failed to read object attrs: %v", err)
	}
	if !attrs.CustomTime.Equal(newerTime) {
		t.Errorf("CustomTime was overwritten: got %v, want %v", attrs.CustomTime, newerTime)
	}
}

func TestHandleGCSRetry_InvalidData(t *testing.T) {
	ctx := context.Background()
	gcsMock := testutils.NewMockStorage()

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			GCS: gcsMock,
		},
	})

	msg := &pubsub.Message{
		Data: []byte("invalid-protobuf-bytes"),
	}

	// Should not error (non-retryable invalid data is acknowledged)
	if err := rec.HandleGCSRetry(ctx, msg); err != nil {
		t.Fatalf("HandleGCSRetry returned error on invalid data: %v", err)
	}
}

func TestHandleGCSMissing_Git(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	publisherMock := &testutils.MockPublisher{}

	// Setup SourceRepository and Vulnerability in Datastore
	sourceRepoStore := osvdatastore.NewSourceRepositoryStore(dsClient)
	err := sourceRepoStore.Update(ctx, "test-git", &models.SourceRepository{
		Name: "test-git",
		Type: models.SourceRepositoryTypeGit,
		Git: &models.SourceRepoGit{
			URL:              "https://github.com/google/test-repo.git",
			Branch:           "main",
			LastSyncedCommit: "abcdef123456",
		},
		Extension: ".yaml",
	})
	if err != nil {
		t.Fatalf("Failed to create SourceRepository: %v", err)
	}

	vulnKey := datastore.NameKey("Vulnerability", "TEST-GIT-1", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test-git:vulns/TEST-GIT-1.yaml",
		Modified: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	gitterMock := &mockGitterClient{
		fileContentFunc: func(_ context.Context, req *gitterpb.FileContentRequest) (*gitterpb.FileContentResponse, error) {
			if req.GetUrl() != "https://github.com/google/test-repo.git" {
				return nil, fmt.Errorf("unexpected URL: %s", req.GetUrl())
			}
			if req.GetCommit() != "abcdef123456" {
				return nil, fmt.Errorf("unexpected commit: %s", req.GetCommit())
			}
			if req.GetPath() != "vulns/TEST-GIT-1.yaml" {
				return nil, fmt.Errorf("unexpected path: %s", req.GetPath())
			}

			yamlContent := `id: TEST-GIT-1
modified: "2025-01-01T00:00:00Z"
summary: "Git test summary"
`

			return &gitterpb.FileContentResponse{Content: []byte(yamlContent)}, nil
		},
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			SourceRepo:      sourceRepoStore,
			GCS:             gcsMock,
			Publisher:       publisherMock,
		},
		GitterClient: gitterMock,
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id": "TEST-GIT-1",
		},
	}

	if err := rec.HandleGCSMissing(ctx, msg); err != nil {
		t.Fatalf("HandleGCSMissing failed: %v", err)
	}

	if len(publisherMock.Messages) != 1 {
		t.Fatalf("Expected 1 published message, got %d", len(publisherMock.Messages))
	}

	pubMsg := publisherMock.Messages[0]
	if pubMsg.Attributes["type"] != "update" {
		t.Errorf("Expected type update, got %s", pubMsg.Attributes["type"])
	}
	if pubMsg.Attributes["source"] != "test-git" {
		t.Errorf("Expected source test-git, got %s", pubMsg.Attributes["source"])
	}
	if pubMsg.Attributes["path"] != "vulns/TEST-GIT-1.yaml" {
		t.Errorf("Expected path vulns/TEST-GIT-1.yaml, got %s", pubMsg.Attributes["path"])
	}
	if pubMsg.Attributes["skip_hash_check"] != "true" {
		t.Errorf("Expected skip_hash_check true, got %s", pubMsg.Attributes["skip_hash_check"])
	}

	var pubVuln osvschema.Vulnerability
	if err := proto.Unmarshal(pubMsg.Data, &pubVuln); err != nil {
		t.Fatalf("Failed to unmarshal published proto: %v", err)
	}
	if pubVuln.GetId() != "TEST-GIT-1" {
		t.Errorf("Expected vuln ID TEST-GIT-1, got %s", pubVuln.GetId())
	}
	if pubVuln.GetSummary() != "Git test summary" {
		t.Errorf("Expected summary 'Git test summary', got %s", pubVuln.GetSummary())
	}
}

func TestHandleGCSMissing_Bucket(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	bucketMock := testutils.NewMockStorage()
	publisherMock := &testutils.MockPublisher{}

	sourceRepoStore := osvdatastore.NewSourceRepositoryStore(dsClient)
	err := sourceRepoStore.Update(ctx, "test-bucket", &models.SourceRepository{
		Name: "test-bucket",
		Type: models.SourceRepositoryTypeBucket,
		Bucket: &models.SourceRepoBucket{
			Name: "test-bucket-name",
		},
		Extension: ".json",
	})
	if err != nil {
		t.Fatalf("Failed to create SourceRepository: %v", err)
	}

	vulnKey := datastore.NameKey("Vulnerability", "TEST-BUCKET-1", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test-bucket:vulns/TEST-BUCKET-1.json",
		Modified: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	jsonContent := `{"id": "TEST-BUCKET-1", "modified": "2025-01-01T00:00:00Z", "summary": "Bucket test summary"}`
	err = bucketMock.WriteObject(ctx, "vulns/TEST-BUCKET-1.json", []byte(jsonContent), nil)
	if err != nil {
		t.Fatalf("Failed to write to bucket mock: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			SourceRepo:      sourceRepoStore,
			GCS:             gcsMock,
			GCSProvider:     &mockStorageProvider{storage: bucketMock},
			Publisher:       publisherMock,
		},
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id": "TEST-BUCKET-1",
		},
	}

	if err := rec.HandleGCSMissing(ctx, msg); err != nil {
		t.Fatalf("HandleGCSMissing failed: %v", err)
	}

	if len(publisherMock.Messages) != 1 {
		t.Fatalf("Expected 1 published message, got %d", len(publisherMock.Messages))
	}
	pubMsg := publisherMock.Messages[0]
	var pubVuln osvschema.Vulnerability
	if err := proto.Unmarshal(pubMsg.Data, &pubVuln); err != nil {
		t.Fatalf("Failed to unmarshal published proto: %v", err)
	}
	if pubVuln.GetId() != "TEST-BUCKET-1" {
		t.Errorf("Expected vuln ID TEST-BUCKET-1, got %s", pubVuln.GetId())
	}
}

func TestHandleGCSMissing_REST(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	publisherMock := &testutils.MockPublisher{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vulns/TEST-REST-1.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": "TEST-REST-1", "modified": "2025-01-01T00:00:00Z", "summary": "REST test summary"}`))
	}))
	defer server.Close()

	sourceRepoStore := osvdatastore.NewSourceRepositoryStore(dsClient)
	err := sourceRepoStore.Update(ctx, "test-rest", &models.SourceRepository{
		Name:      "test-rest",
		Type:      models.SourceRepositoryTypeREST,
		Link:      server.URL,
		Extension: ".json",
	})
	if err != nil {
		t.Fatalf("Failed to create SourceRepository: %v", err)
	}

	vulnKey := datastore.NameKey("Vulnerability", "TEST-REST-1", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test-rest:vulns/TEST-REST-1.json",
		Modified: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			SourceRepo:      sourceRepoStore,
			GCS:             gcsMock,
			Publisher:       publisherMock,
		},
		HTTPClient: server.Client(),
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id": "TEST-REST-1",
		},
	}

	if err := rec.HandleGCSMissing(ctx, msg); err != nil {
		t.Fatalf("HandleGCSMissing failed: %v", err)
	}

	if len(publisherMock.Messages) != 1 {
		t.Fatalf("Expected 1 published message, got %d", len(publisherMock.Messages))
	}
	pubMsg := publisherMock.Messages[0]
	var pubVuln osvschema.Vulnerability
	if err := proto.Unmarshal(pubMsg.Data, &pubVuln); err != nil {
		t.Fatalf("Failed to unmarshal published proto: %v", err)
	}
	if pubVuln.GetId() != "TEST-REST-1" {
		t.Errorf("Expected vuln ID TEST-REST-1, got %s", pubVuln.GetId())
	}
}

func TestHandleGCSGenMismatch_Aliases(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	relationsStore := osvdatastore.NewRelationsStore(dsClient)

	// Populate Datastore
	aliasMod := time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)
	_, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), &osvdatastore.AliasGroup{
		VulnIDs:  []string{"CVE-111", "OSV-111", "TEST-111"},
		Modified: aliasMod,
	})
	if err != nil {
		t.Fatalf("Failed to put AliasGroup: %v", err)
	}

	vulnMod := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	vulnKey := datastore.NameKey("Vulnerability", "TEST-111", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test:TEST-111.yaml",
		Modified: vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	// GCS has TEST-111 with no aliases
	vuln := &osvschema.Vulnerability{
		Id:       "TEST-111",
		Modified: timestamppb.New(vulnMod),
	}
	vulnBytes, _ := proto.Marshal(vuln)
	err = gcsMock.WriteObject(ctx, "all/pb/TEST-111.pb", vulnBytes, &clients.WriteOptions{
		CustomTime: &vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to write to GCS: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			Relations:       relationsStore,
			GCS:             gcsMock,
		},
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id":    "TEST-111",
			"field": "aliases",
		},
	}

	if err := rec.HandleGCSGenMismatch(ctx, msg); err != nil {
		t.Fatalf("HandleGCSGenMismatch failed: %v", err)
	}

	// Read from GCS and verify aliases were updated
	gcsData, err := gcsMock.ReadObject(ctx, "all/pb/TEST-111.pb")
	if err != nil {
		t.Fatalf("Failed to read GCS object: %v", err)
	}
	var updatedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(gcsData, &updatedVuln); err != nil {
		t.Fatalf("Failed to unmarshal GCS proto: %v", err)
	}

	wantAliases := []string{"CVE-111", "OSV-111"}
	if diff := cmp.Diff(wantAliases, updatedVuln.GetAliases()); diff != "" {
		t.Errorf("Aliases mismatch (-want +got):\n%s", diff)
	}
	if !updatedVuln.GetModified().AsTime().Equal(aliasMod) {
		t.Errorf("Modified time mismatch: got %v, want %v", updatedVuln.GetModified().AsTime(), aliasMod)
	}

	// Check Datastore Vulnerability modified time
	var dv osvdatastore.Vulnerability
	if err := dsClient.Get(ctx, vulnKey, &dv); err != nil {
		t.Fatalf("Failed to get Vulnerability: %v", err)
	}
	if !dv.Modified.Equal(aliasMod) {
		t.Errorf("Datastore Vulnerability modified mismatch: got %v, want %v", dv.Modified, aliasMod)
	}
}

func TestHandleGCSGenMismatch_Upstream(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	relationsStore := osvdatastore.NewRelationsStore(dsClient)

	upstreamMod := time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)
	upstreamKey := datastore.NameKey("UpstreamGroup", "TEST-111", nil)
	_, err := dsClient.Put(ctx, upstreamKey, &osvdatastore.UpstreamGroup{
		VulnID:      "TEST-111",
		UpstreamIDs: []string{"UPSTREAM-1"},
		Modified:    upstreamMod,
	})
	if err != nil {
		t.Fatalf("Failed to put UpstreamGroup: %v", err)
	}

	vulnMod := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	vulnKey := datastore.NameKey("Vulnerability", "TEST-111", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test:TEST-111.yaml",
		Modified: vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	vuln := &osvschema.Vulnerability{
		Id:       "TEST-111",
		Modified: timestamppb.New(vulnMod),
	}
	vulnBytes, _ := proto.Marshal(vuln)
	err = gcsMock.WriteObject(ctx, "all/pb/TEST-111.pb", vulnBytes, &clients.WriteOptions{
		CustomTime: &vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to write to GCS: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			Relations:       relationsStore,
			GCS:             gcsMock,
		},
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id":    "TEST-111",
			"field": "upstream",
		},
	}

	if err := rec.HandleGCSGenMismatch(ctx, msg); err != nil {
		t.Fatalf("HandleGCSGenMismatch failed: %v", err)
	}

	gcsData, err := gcsMock.ReadObject(ctx, "all/pb/TEST-111.pb")
	if err != nil {
		t.Fatalf("Failed to read GCS object: %v", err)
	}
	var updatedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(gcsData, &updatedVuln); err != nil {
		t.Fatalf("Failed to unmarshal GCS proto: %v", err)
	}

	wantUpstream := []string{"UPSTREAM-1"}
	if diff := cmp.Diff(wantUpstream, updatedVuln.GetUpstream()); diff != "" {
		t.Errorf("Upstream mismatch (-want +got):\n%s", diff)
	}
	if !updatedVuln.GetModified().AsTime().Equal(upstreamMod) {
		t.Errorf("Modified time mismatch: got %v, want %v", updatedVuln.GetModified().AsTime(), upstreamMod)
	}
}

func TestHandleGCSGenMismatch_Related(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	relationsStore := osvdatastore.NewRelationsStore(dsClient)

	relatedMod := time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)
	relatedKey := datastore.NameKey("RelatedGroup", "TEST-111", nil)
	_, err := dsClient.Put(ctx, relatedKey, &osvdatastore.RelatedGroup{
		RelatedIDs: []string{"RELATED-1"},
		Modified:   relatedMod,
	})
	if err != nil {
		t.Fatalf("Failed to put RelatedGroup: %v", err)
	}

	vulnMod := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	vulnKey := datastore.NameKey("Vulnerability", "TEST-111", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test:TEST-111.yaml",
		Modified: vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	vuln := &osvschema.Vulnerability{
		Id:       "TEST-111",
		Modified: timestamppb.New(vulnMod),
	}
	vulnBytes, _ := proto.Marshal(vuln)
	err = gcsMock.WriteObject(ctx, "all/pb/TEST-111.pb", vulnBytes, &clients.WriteOptions{
		CustomTime: &vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to write to GCS: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			Relations:       relationsStore,
			GCS:             gcsMock,
		},
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id":    "TEST-111",
			"field": "related",
		},
	}

	if err := rec.HandleGCSGenMismatch(ctx, msg); err != nil {
		t.Fatalf("HandleGCSGenMismatch failed: %v", err)
	}

	gcsData, err := gcsMock.ReadObject(ctx, "all/pb/TEST-111.pb")
	if err != nil {
		t.Fatalf("Failed to read GCS object: %v", err)
	}
	var updatedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(gcsData, &updatedVuln); err != nil {
		t.Fatalf("Failed to unmarshal GCS proto: %v", err)
	}

	wantRelated := []string{"RELATED-1"}
	if diff := cmp.Diff(wantRelated, updatedVuln.GetRelated()); diff != "" {
		t.Errorf("Related mismatch (-want +got):\n%s", diff)
	}
	if !updatedVuln.GetModified().AsTime().Equal(relatedMod) {
		t.Errorf("Modified time mismatch: got %v, want %v", updatedVuln.GetModified().AsTime(), relatedMod)
	}
}

func TestHandleGCSGenMismatch_MultipleFieldsWithSpaces(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	gcsMock := testutils.NewMockStorage()
	relationsStore := osvdatastore.NewRelationsStore(dsClient)

	aliasMod := time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)
	_, err := dsClient.Put(ctx, datastore.IncompleteKey("AliasGroup", nil), &osvdatastore.AliasGroup{
		VulnIDs:  []string{"CVE-222", "TEST-222"},
		Modified: aliasMod,
	})
	if err != nil {
		t.Fatalf("Failed to put AliasGroup: %v", err)
	}

	upstreamMod := time.Date(2025, 3, 3, 0, 0, 0, 0, time.UTC)
	upstreamKey := datastore.NameKey("UpstreamGroup", "TEST-222", nil)
	_, err = dsClient.Put(ctx, upstreamKey, &osvdatastore.UpstreamGroup{
		VulnID:      "TEST-222",
		UpstreamIDs: []string{"UPSTREAM-2"},
		Modified:    upstreamMod,
	})
	if err != nil {
		t.Fatalf("Failed to put UpstreamGroup: %v", err)
	}

	vulnMod := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	vulnKey := datastore.NameKey("Vulnerability", "TEST-222", nil)
	_, err = dsClient.Put(ctx, vulnKey, &osvdatastore.Vulnerability{
		SourceID: "test:TEST-222.yaml",
		Modified: vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to put Vulnerability: %v", err)
	}

	vuln := &osvschema.Vulnerability{
		Id:       "TEST-222",
		Modified: timestamppb.New(vulnMod),
	}
	vulnBytes, _ := proto.Marshal(vuln)
	err = gcsMock.WriteObject(ctx, "all/pb/TEST-222.pb", vulnBytes, &clients.WriteOptions{
		CustomTime: &vulnMod,
	})
	if err != nil {
		t.Fatalf("Failed to write to GCS: %v", err)
	}

	rec := recoverer.New(recoverer.Config{
		Stores: recoverer.Stores{
			DatastoreClient: dsClient,
			Relations:       relationsStore,
			GCS:             gcsMock,
		},
	})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"id":    "TEST-222",
			"field": "aliases, upstream",
		},
	}

	if err := rec.HandleGCSGenMismatch(ctx, msg); err != nil {
		t.Fatalf("HandleGCSGenMismatch failed: %v", err)
	}

	gcsData, err := gcsMock.ReadObject(ctx, "all/pb/TEST-222.pb")
	if err != nil {
		t.Fatalf("Failed to read GCS object: %v", err)
	}
	var updatedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(gcsData, &updatedVuln); err != nil {
		t.Fatalf("Failed to unmarshal GCS proto: %v", err)
	}

	wantAliases := []string{"CVE-222"}
	if diff := cmp.Diff(wantAliases, updatedVuln.GetAliases()); diff != "" {
		t.Errorf("Aliases mismatch (-want +got):\n%s", diff)
	}
	wantUpstream := []string{"UPSTREAM-2"}
	if diff := cmp.Diff(wantUpstream, updatedVuln.GetUpstream()); diff != "" {
		t.Errorf("Upstream mismatch (-want +got):\n%s", diff)
	}
	if !updatedVuln.GetModified().AsTime().Equal(upstreamMod) {
		t.Errorf("Modified time mismatch: got %v, want %v", updatedVuln.GetModified().AsTime(), upstreamMod)
	}
}

func TestHandleGeneric(t *testing.T) {
	ctx := context.Background()
	rec := recoverer.New(recoverer.Config{})

	msg := &pubsub.Message{
		Attributes: map[string]string{
			"type": "custom_unknown_task",
		},
	}

	if err := rec.HandleGeneric(ctx, msg); err != nil {
		t.Fatalf("HandleGeneric returned error: %v", err)
	}
}
