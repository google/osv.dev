package namenormalize

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

	vuln := &osvschema.Vulnerability{
		Id: "TEST-123",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "Flask",
				},
			},
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "A_B-C.D",
				},
			},
			{
				Package: &osvschema.Package{
					Ecosystem: "npm",
					Name:      "Flask",
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

	affected := vuln.GetAffected()

	if affected[0].GetPackage().GetName() != "flask" {
		t.Errorf("Expected flask, got %s", affected[0].GetPackage().GetName())
	}

	if affected[1].GetPackage().GetName() != "a-b-c-d" {
		t.Errorf("Expected a-b-c-d, got %s", affected[1].GetPackage().GetName())
	}

	if affected[2].GetPackage().GetName() != "Flask" {
		t.Errorf("Expected Flask, got %s", affected[2].GetPackage().GetName())
	}
}
