package enumerateversions

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	r := testutils.SetupVCR(t)
	provider := ecosystem.NewProvider(r.GetDefaultClient())

	vuln := &osvschema.Vulnerability{
		Id: "TEST-123",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "atomicwrites",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							// events are intentionally out of order
							{Fixed: "1.4.1"},
							{Introduced: "1.3.0"},
						},
					},
				},
			},
		},
	}

	params := &pipeline.EnrichParams{
		EcosystemProvider: provider,
	}

	if err := enricher.Enrich(ctx, vuln, params); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	affected := vuln.GetAffected()[0]
	versions := affected.GetVersions()

	if len(versions) == 0 {
		t.Fatalf("Expected enumerated versions, got none")
	}

	expectedVersions := []string{"1.3.0", "1.4.0"}
	if diff := cmp.Diff(expectedVersions, versions); diff != "" {
		t.Errorf("Enricher versions mismatch (-want +got):\n%s", diff)
	}
}

func TestEnricher_Enrich_ParseError(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	r := testutils.SetupVCR(t)
	provider := ecosystem.NewProvider(r.GetDefaultClient())

	vuln := &osvschema.Vulnerability{
		Id: "TEST-124",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "CRAN",
					Name:      "stringr",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "!!!"},
						},
					},
				},
			},
		},
	}

	params := &pipeline.EnrichParams{
		EcosystemProvider: provider,
	}

	if err := enricher.Enrich(ctx, vuln, params); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	affected := vuln.GetAffected()[0]
	versions := affected.GetVersions()

	// We expect no versions to be added because the range should be skipped due to parse error.
	if len(versions) != 0 {
		t.Errorf("Expected no versions due to parse error, got %v", versions)
	}
}
