// Package schemaversion implements an enricher that sets the schema_version to the latest for the vulnerability.
package schemaversion

import (
	"context"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(_ context.Context, vuln *osvschema.Vulnerability, _ *pipeline.EnrichParams) error {
	// TODO(michaelkedar): we've had problems with this not staying up-to-date in the past
	vuln.SchemaVersion = osvconstants.SchemaVersion

	return nil
}
