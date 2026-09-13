package worker

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// countingSourceRepoStore records whether the engine got as far as looking up
// the source repository, which is the first thing handleUpdate does.
type countingSourceRepoStore struct {
	models.SourceRepositoryStore

	getCalls int
}

func (m *countingSourceRepoStore) Get(_ context.Context, _ string) (*models.SourceRepository, error) {
	m.getCalls++

	return nil, errors.New("stop here")
}

// countingVulnerabilityStore records whether the engine got as far as looking
// up the existing record, which is the first thing handleDelete does.
type countingVulnerabilityStore struct {
	models.VulnerabilityStore

	getWithMetadataCalls int
}

func (m *countingVulnerabilityStore) GetWithMetadata(_ context.Context, _ string) (*osvschema.Vulnerability, *models.VulnSourceRef, error) {
	m.getWithMetadataCalls++

	return nil, nil, models.ErrNotFound
}

var _ models.SourceRepositoryStore = (*countingSourceRepoStore)(nil)
var _ models.VulnerabilityStore = (*countingVulnerabilityStore)(nil)

func TestHandleMessageDropsUpdateWithNoPayload(t *testing.T) {
	sourceRepo := &countingSourceRepoStore{}
	sub := Subscriber{Engine: Engine{Stores: Stores{SourceRepo: sourceRepo}}}

	// This is what publishUpdate publishes for a record too large to fit in a
	// Pub/Sub message: no data, but still flagged as an update.
	m := &pubsub.Message{Attributes: map[string]string{
		"type":    "update",
		"source":  "test-source",
		"path":    "test-source/GHSA-1234-5678-9012.json",
		"deleted": "false",
	}}

	sub.handleMessage(context.Background(), m)

	if sourceRepo.getCalls != 0 {
		t.Errorf("engine was handed an update with no payload, SourceRepo.Get called %d time(s)", sourceRepo.getCalls)
	}
}

func TestHandleMessageStillProcessesEmptyDeletion(t *testing.T) {
	vulnStore := &countingVulnerabilityStore{}
	sub := Subscriber{Engine: Engine{Stores: Stores{Vulnerability: vulnStore}}}

	// Deletions are also published with no data and must keep working.
	m := &pubsub.Message{Attributes: map[string]string{
		"type":    "update",
		"source":  "test-source",
		"path":    "test-source/GHSA-1234-5678-9012.json",
		"deleted": "true",
	}}

	sub.handleMessage(context.Background(), m)

	if vulnStore.getWithMetadataCalls != 1 {
		t.Errorf("deletion did not reach the engine, GetWithMetadata called %d time(s)", vulnStore.getWithMetadataCalls)
	}
}
