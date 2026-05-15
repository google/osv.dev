// Package enumerateversions implements an enricher that populates the affected[].versions field for supported ecosystems.
package enumerateversions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/osv.dev/go/internal/osvutil"
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
			continue
		}
		enumerableSys, ok := sys.(ecosystem.Enumerable)
		if !ok {
			// Only ecosystems that implement Enumerable can have their versions enumerated.
			continue
		}
		allVersions, err := enumerableSys.GetVersions(pkg.GetName())
		if errors.Is(err, ecosystem.ErrPackageNotFound) {
			// The package doesn't exist in this ecosystem, so we can't enumerate its versions.
			logger.WarnContext(ctx, "package not found in ecosystem",
				slog.String("vuln_id", vuln.GetId()),
				slog.String("package", pkg.GetName()),
				slog.String("ecosystem", ecosystemName))

			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get versions for package %s in ecosystem %s: %w", pkg.GetName(), ecosystemName, err)
		}

		var newVersions []string

	RangeLoop:
		for _, r := range affected.GetRanges() {
			if r.GetType() != osvschema.Range_ECOSYSTEM && r.GetType() != osvschema.Range_SEMVER {
				continue
			}

			// 1. Convert schema events to the internal Event struct.
			var events []osvutil.Event
			for _, e := range r.GetEvents() {
				evt := osvutil.FromSchemaEvent(e)
				if evt.Version == "" {
					continue
				}
				if evt.Type == osvutil.Limit && evt.Version == "*" {
					// We shouldn't get limit events, but if we do,
					// limit: "*" is a valid value for indicating no limit.
					continue
				}
				events = append(events, evt)
			}

			// 2. Sort the events chronologically.
			if err := osvutil.SortEvents(sys, events); err != nil {
				logger.ErrorContext(ctx, "failed to sort events, skipping range",
					slog.String("vuln_id", vuln.GetId()),
					slog.String("package", pkg.GetName()),
					slog.String("ecosystem", ecosystemName),
					slog.String("error", err.Error()))

				continue
			}

			// 3. Cache parsed versions to avoid repetitive parsing.
			type parsedEvent struct {
				osvutil.Event

				Parsed ecosystem.Version
			}

			var parsedEvents []parsedEvent
			for _, evt := range events {
				p, err := sys.Parse(evt.Version)
				if err != nil {
					logger.ErrorContext(ctx, "failed to parse event version, skipping range",
						slog.String("vuln_id", vuln.GetId()),
						slog.String("package", pkg.GetName()),
						slog.String("ecosystem", ecosystemName),
						slog.String("version", evt.Version),
						slog.String("error", err.Error()))

					continue RangeLoop
				}
				parsedEvents = append(parsedEvents, parsedEvent{Event: evt, Parsed: p})
			}

			// 4. Walk both versions and events simultaneously.
			eventIdx := 0
			isAffected := false

			for _, vStr := range allVersions {
				vParsed, err := sys.Parse(vStr)
				if err != nil {
					continue
				}

				for eventIdx < len(parsedEvents) {
					evt := parsedEvents[eventIdx]
					cmp, _ := evt.Parsed.Compare(vParsed)

					if cmp < 0 {
						switch evt.Type {
						case osvutil.Introduced:
							isAffected = true
						case osvutil.Fixed, osvutil.LastAffected, osvutil.Limit:
							isAffected = false
						}
						eventIdx++

						continue
					}

					if cmp == 0 {
						switch evt.Type {
						case osvutil.Introduced:
							isAffected = true
						case osvutil.Fixed, osvutil.Limit: // treat limit as fixed
							isAffected = false
						case osvutil.LastAffected:
							newVersions = append(newVersions, vStr)
							isAffected = false
						}
						eventIdx++

						continue
					}

					if cmp > 0 {
						break
					}
				}

				if isAffected {
					newVersions = append(newVersions, vStr)
				}
			}
		}

		if len(newVersions) > 0 {
			// Append newly discovered versions to the end.
			versions := append(affected.GetVersions(), newVersions...)
			// Deduplicate by sorting and compacting.
			slices.Sort(versions)
			versions = slices.Compact(versions)
			affected.Versions = versions
		}
	}

	return nil
}
