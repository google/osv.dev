// Package purl implements an enricher that adds missing PURLs to affected packages, and cleans up some invalid PURLs.
package purl

import (
	"context"
	"log/slog"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	packageurl "github.com/package-url/packageurl-go"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

func (*Enricher) Enrich(ctx context.Context, vuln *osvschema.Vulnerability, _ *pipeline.EnrichParams) error {
	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		if purlStr := pkg.GetPurl(); purlStr != "" {
			pkgPURL, err := packageurl.FromString(purlStr)
			if err == nil {
				if pkgPURL.Version != "" {
					logger.WarnContext(ctx, "package has purl with version, stripping",
						slog.String("purl", purlStr),
						slog.String("vuln_id", vuln.GetId()),
						slog.String("ecosystem", pkg.GetEcosystem()),
						slog.String("name", pkg.GetName()),
					)
					pkgPURL.Version = ""
					pkg.Purl = pkgPURL.ToString()
				}
				// PURL is valid, nothing to do.
				continue
			}

			// PURL is invalid, discard it
			logger.ErrorContext(ctx, "package has invalid purl, discarding",
				slog.String("purl", purlStr),
				slog.String("vuln_id", vuln.GetId()),
				slog.String("ecosystem", pkg.GetEcosystem()),
				slog.String("name", pkg.GetName()),
				slog.Any("error", err),
			)
			pkg.Purl = ""
		}

		// We require an ecosystem and a name to form a PURL
		if pkg.GetEcosystem() == "" || pkg.GetName() == "" {
			continue
		}

		purlStr, err := purl.Generate(pkg.GetEcosystem(), pkg.GetName())
		if err != nil {
			logger.WarnContext(ctx, "failed to generate purl",
				slog.String("vuln_id", vuln.GetId()),
				slog.String("ecosystem", pkg.GetEcosystem()),
				slog.String("name", pkg.GetName()),
				slog.Any("error", err),
			)

			continue
		}
		pkg.Purl = purlStr
	}

	return nil
}
