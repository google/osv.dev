// Package enrich contains individual vulnerability enrichers for the worker pipeline.
package enrich

import (
	"context"

	"github.com/google/osv.dev/go/internal/worker"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

type SourceLinkAdder struct{}

var _ worker.Enricher = (*SourceLinkAdder)(nil)

func (*SourceLinkAdder) Enrich(_ context.Context, vuln *osvschema.Vulnerability, params *worker.EnrichParams) error {
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
