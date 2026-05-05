package sourcelink

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
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
					Name:      "flask",
				},
			},
		},
	}

	params := &pipeline.EnrichParams{
		PathInSource: "/vulns/TEST-123.json",
		SourceRepo: &models.SourceRepository{
			Link: "https://github.com/example/repo",
		},
	}

	if err := enricher.Enrich(ctx, vuln, params); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	affected := vuln.GetAffected()
	dbSpecific := affected[0].GetDatabaseSpecific()
	if dbSpecific == nil {
		t.Fatalf("Expected DatabaseSpecific to be populated, got nil")
	}

	sourceVal, ok := dbSpecific.GetFields()["source"]
	if !ok {
		t.Fatalf("Expected 'source' field in DatabaseSpecific, but not found")
	}

	expectedLink := "https://github.com/example/repo/vulns/TEST-123.json"
	if sourceVal.GetStringValue() != expectedLink {
		t.Errorf("Expected source %q, got %q", expectedLink, sourceVal.GetStringValue())
	}
}

func TestEnricher_Enrich_NoSourceRepo(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	vuln := &osvschema.Vulnerability{
		Id: "TEST-123",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "flask",
				},
			},
		},
	}

	params := &pipeline.EnrichParams{
		PathInSource: "/vulns/TEST-123.json",
		SourceRepo:   nil,
	}

	if err := enricher.Enrich(ctx, vuln, params); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	affected := vuln.GetAffected()
	if affected[0].GetDatabaseSpecific() != nil {
		t.Errorf("Expected DatabaseSpecific to be nil, got %v", affected[0].GetDatabaseSpecific())
	}
}
