package worker

import (
	"context"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type Stores struct {
	SourceRepo    models.SourceRepositoryStore
	Vulnerability models.VulnerabilityStore
}

type EnrichParams struct {
	PathInSource string
	SourceRepo   *models.SourceRepository
}

type Enricher interface {
	Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *EnrichParams) error
}
