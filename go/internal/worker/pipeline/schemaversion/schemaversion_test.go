package schemaversion

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	vuln := &osvschema.Vulnerability{
		Id:            "TEST-123",
		SchemaVersion: "1.0.0",
	}

	if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{}); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if vuln.GetSchemaVersion() != osvconstants.SchemaVersion {
		t.Errorf("Expected schema_version %s, got %s", osvconstants.SchemaVersion, vuln.GetSchemaVersion())
	}
}
