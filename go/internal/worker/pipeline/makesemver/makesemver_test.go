package makesemver

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	tests := []struct {
		name         string
		ecosystem    string
		rangeType    osvschema.Range_Type
		events       []*osvschema.Event
		expectedType osvschema.Range_Type
	}{
		{
			name:      "Convert ECOSYSTEM to SEMVER for SemVer ecosystem with valid SemVer",
			ecosystem: "npm",
			rangeType: osvschema.Range_ECOSYSTEM,
			events: []*osvschema.Event{
				{Introduced: "0"},
				{Fixed: "1.2.3"},
			},
			expectedType: osvschema.Range_SEMVER,
		},
		{
			name:      "Do not convert for SemVer ecosystem with invalid SemVer events",
			ecosystem: "npm",
			rangeType: osvschema.Range_ECOSYSTEM,
			events: []*osvschema.Event{
				{Introduced: "1.0"}, // Missing patch version
			},
			expectedType: osvschema.Range_ECOSYSTEM,
		},
		{
			name:      "Do not convert for non-SemVer ecosystem",
			ecosystem: "PyPI",
			rangeType: osvschema.Range_ECOSYSTEM,
			events: []*osvschema.Event{
				{Introduced: "1.2.3"},
			},
			expectedType: osvschema.Range_ECOSYSTEM,
		},
		{
			name:      "Do not convert other range types",
			ecosystem: "npm",
			rangeType: osvschema.Range_GIT,
			events: []*osvschema.Event{
				{Introduced: "1.2.3"},
			},
			expectedType: osvschema.Range_GIT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Id: "TEST-123",
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: tc.ecosystem,
							Name:      "test-pkg",
						},
						Ranges: []*osvschema.Range{
							{
								Type:   tc.rangeType,
								Events: tc.events,
							},
						},
					},
				},
			}

			params := &pipeline.EnrichParams{
				EcosystemProvider: ecosystem.DefaultProvider,
			}

			if err := enricher.Enrich(ctx, vuln, params); err != nil {
				t.Fatalf("Enrich failed: %v", err)
			}

			ranges := vuln.GetAffected()[0].GetRanges()
			if ranges[0].GetType() != tc.expectedType {
				t.Errorf("Expected range type %v, got %v", tc.expectedType, ranges[0].GetType())
			}
		})
	}
}
