// Package published implements an enricher that sets the published date if missing from the vulnerability.
package published

import (
	"context"

	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(_ context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	// published is set, nothing to do
	if vuln.GetPublished() != nil {
		return nil
	}
	// we have an existing vuln with a published date, carry it forward
	if params.ExistingVuln != nil && params.ExistingVuln.GetPublished() != nil {
		vuln.Published = params.ExistingVuln.GetPublished()
		return nil
	}
	// Otherwise, set it to the raw modified date
	vuln.Published = vuln.GetModified()

	return nil
}
