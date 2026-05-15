package published

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	published1 := timestamppb.Now()
	// create a slightly different timestamp for the existing one
	published2 := &timestamppb.Timestamp{Seconds: published1.GetSeconds() + 100}
	modified1 := &timestamppb.Timestamp{Seconds: published1.GetSeconds() + 200}

	tests := []struct {
		name              string
		initialPublished  *timestamppb.Timestamp
		existingPublished *timestamppb.Timestamp
		modified          *timestamppb.Timestamp
		expectedPublished *timestamppb.Timestamp
	}{
		{
			name:              "Preserve existing published",
			initialPublished:  published1,
			existingPublished: published2,
			modified:          modified1,
			expectedPublished: published1,
		},
		{
			name:              "Carry forward published from existing vuln",
			initialPublished:  nil,
			existingPublished: published2,
			modified:          modified1,
			expectedPublished: published2,
		},
		{
			name:              "Default to modified if missing everywhere",
			initialPublished:  nil,
			existingPublished: nil,
			modified:          modified1,
			expectedPublished: modified1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Id:        "TEST-123",
				Published: tc.initialPublished,
				Modified:  tc.modified,
			}

			var existing *osvschema.Vulnerability
			if tc.existingPublished != nil {
				existing = &osvschema.Vulnerability{
					Id:        "TEST-123",
					Published: tc.existingPublished,
				}
			}

			params := &pipeline.EnrichParams{
				ExistingVuln: existing,
			}

			if err := enricher.Enrich(ctx, vuln, params); err != nil {
				t.Fatalf("Enrich failed: %v", err)
			}

			if !proto.Equal(vuln.GetPublished(), tc.expectedPublished) {
				t.Errorf("Expected published %v, got %v", tc.expectedPublished, vuln.GetPublished())
			}
		})
	}
}
