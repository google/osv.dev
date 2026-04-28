// Package pipeline contains individual vulnerability enrichers for the worker pipeline.
package pipeline

import (
	"context"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type EnrichParams struct {
	PathInSource string
	SourceRepo   *models.SourceRepository
}

type Enricher interface {
	Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *EnrichParams) error
}
