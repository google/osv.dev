// Package makesemver implements an enricher that converts affected[].ranges[].type to SEMVER from ECOSYSTEM
// for SEMVER ecosystems.
package makesemver

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type Enricher struct{}

var _ pipeline.Enricher = (*Enricher)(nil)

// https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
var strictSemverRegex = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

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
		if !ok || !sys.IsSemver() {
			continue
		}
		for _, r := range affected.GetRanges() {
			if r.GetType() != osvschema.Range_ECOSYSTEM {
				continue
			}
			// We only want to convert ECOSYSTEM ranges to SEMVER ranges if all events
			// in the range use valid SEMVER strings.
			// See: https://github.com/google/osv.dev/issues/5173
			isValidSemverRange := true
			for _, e := range r.GetEvents() {
				var eventValue string
				switch {
				case e.GetIntroduced() != "":
					eventValue = e.GetIntroduced()
				case e.GetFixed() != "":
					eventValue = e.GetFixed()
				case e.GetLastAffected() != "":
					eventValue = e.GetLastAffected()
					// skipping limit events because they don't make sense here
				}
				if eventValue != "0" && !strictSemverRegex.MatchString(eventValue) {
					logger.WarnContext(ctx, "non-semver version found in semver ecosystem range",
						slog.String("vuln_id", vuln.GetId()),
						slog.String("ecosystem", ecosystemName),
						slog.String("event_value", eventValue))
					isValidSemverRange = false

					break
				}
			}
			if isValidSemverRange {
				r.Type = osvschema.Range_SEMVER
			}
		}
	}

	return nil
}
