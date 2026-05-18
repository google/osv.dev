package relations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockRelationsStore struct {
	aliases  *models.GetAliasResult
	related  *models.GetRelatedResult
	upstream *models.GetUpstreamResult
	err      error
}

func (m *mockRelationsStore) GetAliases(_ context.Context, _ string) (*models.GetAliasResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.aliases == nil {
		return nil, models.ErrNotFound
	}

	return m.aliases, nil
}

func (m *mockRelationsStore) GetRelated(_ context.Context, _ string) (*models.GetRelatedResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.related == nil {
		return nil, models.ErrNotFound
	}

	return m.related, nil
}

func (m *mockRelationsStore) GetUpstream(_ context.Context, _ string) (*models.GetUpstreamResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.upstream == nil {
		return nil, models.ErrNotFound
	}

	return m.upstream, nil
}

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	earlier := now.Add(-1 * time.Hour)
	later := now.Add(1 * time.Hour)

	tests := []struct {
		name         string
		initialVuln  *osvschema.Vulnerability
		mockStore    *mockRelationsStore
		expectedVuln *osvschema.Vulnerability
		expectedErr  bool
	}{
		{
			name: "Populate all relations and update modified",
			initialVuln: &osvschema.Vulnerability{
				Id:       "TEST-123",
				Modified: timestamppb.New(now),
			},
			mockStore: &mockRelationsStore{
				aliases: &models.GetAliasResult{
					Aliases:  []string{"ALIAS-1"},
					Modified: later,
				},
				related: &models.GetRelatedResult{
					Related:  []string{"RELATED-1"},
					Modified: now, // same, should not update modified
				},
				upstream: &models.GetUpstreamResult{
					Upstream: []string{"UPSTREAM-1"},
					Modified: earlier, // earlier, should not update modified
				},
			},
			expectedVuln: &osvschema.Vulnerability{
				Id:       "TEST-123",
				Aliases:  []string{"ALIAS-1"},
				Related:  []string{"RELATED-1"},
				Upstream: []string{"UPSTREAM-1"},
				Modified: timestamppb.New(later),
			},
			expectedErr: false,
		},
		{
			name: "Relations not found (silent ignore)",
			initialVuln: &osvschema.Vulnerability{
				Id:       "TEST-123",
				Modified: timestamppb.New(now),
			},
			mockStore: &mockRelationsStore{}, // returns ErrNotFound for all
			expectedVuln: &osvschema.Vulnerability{
				Id:       "TEST-123",
				Modified: timestamppb.New(now),
			},
			expectedErr: false,
		},
		{
			name: "Store error propagates",
			initialVuln: &osvschema.Vulnerability{
				Id: "TEST-123",
			},
			mockStore: &mockRelationsStore{
				err: errors.New("DB error"),
			},
			expectedVuln: &osvschema.Vulnerability{
				Id: "TEST-123",
			},
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := &pipeline.EnrichParams{
				RelationsStore: tc.mockStore,
			}

			vuln := tc.initialVuln // in-place modification

			err := enricher.Enrich(ctx, vuln, params)
			if (err != nil) != tc.expectedErr {
				t.Fatalf("Enrich() error = %v, wantErr %v", err, tc.expectedErr)
			}

			if tc.expectedErr {
				return
			}

			if diff := cmp.Diff(tc.expectedVuln, vuln, protocmp.Transform()); diff != "" {
				t.Errorf("Vulnerability mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEnricher_Enrich_NilStore(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()
	vuln := &osvschema.Vulnerability{Id: "TEST-123"}

	err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{RelationsStore: nil})
	if err == nil || err.Error() != "relations store not provided" {
		t.Errorf("Expected 'relations store not provided' error, got %v", err)
	}
}
