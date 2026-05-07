package filterecosystem

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	tests := []struct {
		name             string
		repoName         string
		affected         []*osvschema.Affected
		expectedAffected []*osvschema.Affected
	}{
		{
			name:     "Keep valid ecosystem",
			repoName: "all-allowed",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "atomicwrites",
					},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "atomicwrites",
					},
				},
			},
		},
		{
			name:     "Filter out invalid ecosystem",
			repoName: "all-allowed",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "InvalidEcosystem",
						Name:      "pkg",
					},
				},
			},
			expectedAffected: []*osvschema.Affected{},
		},
		{
			name:     "Filter out non-Echo for Echo repo",
			repoName: "echo",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "atomicwrites",
					},
				},
			},
			expectedAffected: []*osvschema.Affected{},
		},
		{
			name:     "Keep Echo for Echo repo",
			repoName: "echo",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "Echo",
						Name:      "pkg",
					},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "Echo",
						Name:      "pkg",
					},
				},
			},
		},
		{
			name:     "Preserve GIT ranges when filtering ecosystem",
			repoName: "all-allowed",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "InvalidEcosystem",
						Name:      "pkg",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/example/repo",
							Events: []*osvschema.Event{
								{Introduced: "0"},
							},
						},
						{
							Type: osvschema.Range_ECOSYSTEM,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
							},
						},
					},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/example/repo",
							Events: []*osvschema.Event{
								{Introduced: "0"},
							},
						},
					},
				},
			},
		},
		{
			name:     "Mixed valid and invalid ecosystems",
			repoName: "all-allowed",
			affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "valid-pkg",
					},
				},
				{
					Package: &osvschema.Package{
						Ecosystem: "InvalidEcosystem",
						Name:      "invalid-pkg",
					},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Name:      "valid-pkg",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Id:       "TEST-123",
				Affected: tc.affected,
			}

			params := &pipeline.EnrichParams{
				SourceRepo: &models.SourceRepository{
					Name: tc.repoName,
				},
			}

			if err := enricher.Enrich(ctx, vuln, params); err != nil {
				t.Fatalf("Enrich failed: %v", err)
			}

			opts := []cmp.Option{
				protocmp.Transform(),
			}

			if diff := cmp.Diff(tc.expectedAffected, vuln.GetAffected(), opts...); diff != "" {
				t.Errorf("Affected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
