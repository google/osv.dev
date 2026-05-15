// Package filterecosystem implements an enricher that filters out affected ecosystems that should not be there.
package filterecosystem

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/osvutil/schema"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, params *pipeline.EnrichParams) error {
	newAffected := make([]*osvschema.Affected, 0, len(vuln.GetAffected()))
	acceptedEcos := params.SourceRepo.AcceptedEcosystems
	allowAll := slices.Contains(acceptedEcos, "*")
	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		if pkg == nil {
			continue
		}
		ecosystem := pkg.GetEcosystem()
		ecoBase, _, _ := strings.Cut(ecosystem, ":")
		shouldRemove := false
		if !allowAll && !slices.Contains(acceptedEcos, osvconstants.Ecosystem(ecoBase)) {
			shouldRemove = true
		}
		if !schema.IsKnownEcosystem(ecoBase) {
			shouldRemove = true
		}
		if !shouldRemove {
			newAffected = append(newAffected, affected)
			continue
		}
		logger.WarnContext(ctx, "filtered out affected ecosystem",
			slog.String("vuln_id", vuln.GetId()),
			slog.String("ecosystem", ecosystem),
			slog.String("repo", params.SourceRepo.Name))

		// check if there any GIT affected ranges that we might want to keep
		gitRanges := make([]*osvschema.Range, 0, len(affected.GetRanges()))
		for _, r := range affected.GetRanges() {
			if r.GetType() == osvschema.Range_GIT {
				gitRanges = append(gitRanges, r)
			}
		}
		if len(gitRanges) > 0 {
			aff := proto.Clone(affected).(*osvschema.Affected)
			aff.Ranges = gitRanges
			aff.Package = nil
			newAffected = append(newAffected, aff)
		}
	}
	vuln.Affected = newAffected

	return nil
}
