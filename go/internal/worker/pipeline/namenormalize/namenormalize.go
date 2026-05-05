// Package namenormalize implements an enricher that normalizes package names in a vulnerability.
package namenormalize

import (
	"context"
	"log/slog"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	provider := params.EcosystemProvider
	if provider == nil {
		logger.WarnContext(ctx, "ecosystem provider is nil, using default", slog.String("vuln_id", vuln.GetId()))
		provider = ecosystem.DefaultProvider
	}
	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		ecosystemName := pkg.GetEcosystem()
		if ecosystemName == "" {
			continue
		}
		sys, ok := provider.Get(ecosystemName)
		if !ok {
			// Ecosystem not found - other enrichers can log better warnings about this.
			continue
		}
		pkg.Name = ecosystem.NormalizePackageName(sys, pkg.GetName())
	}

	return nil
}
