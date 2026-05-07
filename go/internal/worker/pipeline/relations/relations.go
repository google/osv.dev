// Package relations implements an enricher that populates computed alisases, related, and upstream ids.
package relations

import (
	"context"
	"errors"
	"fmt"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	rs := params.RelationsStore
	if rs == nil {
		return errors.New("relations store not provided")
	}

	aliases, err := rs.GetAliases(ctx, vuln.GetId())
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return fmt.Errorf("failed getting aliases: %w", err)
	} else if err == nil {
		vuln.Aliases = aliases.Aliases
		if vuln.GetModified().AsTime().Before(aliases.Modified) {
			vuln.Modified = timestamppb.New(aliases.Modified)
		}
	}

	related, err := rs.GetRelated(ctx, vuln.GetId())
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return fmt.Errorf("failed getting related: %w", err)
	} else if err == nil {
		vuln.Related = related.Related
		if vuln.GetModified().AsTime().Before(related.Modified) {
			vuln.Modified = timestamppb.New(related.Modified)
		}
	}

	upstream, err := rs.GetUpstream(ctx, vuln.GetId())
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return fmt.Errorf("failed getting upstream: %w", err)
	} else if err == nil {
		vuln.Upstream = upstream.Upstream
		if vuln.GetModified().AsTime().Before(upstream.Modified) {
			vuln.Modified = timestamppb.New(upstream.Modified)
		}
	}

	return nil
}
