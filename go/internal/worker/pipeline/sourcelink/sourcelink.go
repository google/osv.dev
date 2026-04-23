// Package sourcelink implements an enricher that adds the source link to the vulnerability.
// The source link is added under the database_specific field under each affected range,
// with they key "source" and the value being the full path to the vulnerability in the source repo.
package sourcelink

import (
	"context"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(_ context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	if params.SourceRepo == nil || params.SourceRepo.Link == "" {
		return nil
	}
	sourceLink := structpb.NewStringValue(params.SourceRepo.Link + params.PathInSource)

	for _, affected := range vuln.GetAffected() {
		if affected.GetDatabaseSpecific() == nil {
			// The error would only be from an invalid map value, passing nil is fine.
			affected.DatabaseSpecific, _ = structpb.NewStruct(nil)
		}
		affected.DatabaseSpecific.Fields["source"] = sourceLink
	}

	return nil
}
